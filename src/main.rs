//! YAM registry.  Artifacts are accepted only after validation and metadata is
//! published as an atomically replaced, detached-Ed25519-signed static tree.
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{AppendHeaders, Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::{Cursor, Read},
    net::SocketAddr,
    path::{Component, Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};

const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_NAMESPACES_PER_USER: i64 = 2;
/// Quasar platform identifiers for devices on which YAM packages can run.
///
/// TVs, modules, hubs, cameras and headphones deliberately do not appear
/// here: they are not supported YAM installation targets. `yandexplum` is a
/// legacy YAM profile name for the `plum` (Station Lite 2) platform.
const SUPPORTED_DEVICE_TARGETS: &[&str] = &[
    "yandexstation",
    "yandexstation_2",
    "yandexmini",
    "yandexmini_2",
    "bergamot",
    "yandexmicro",
    "plum",
    "yandexplum",
    "yandexmidi",
    "cucumber",
    "chiron",
    "orion",
    "mango",
    "pickle",
    "lightcomm",
    "elari_a98",
    "linkplay_a98",
    "wk7y",
    "prestigio_smart_mate",
    "jbl_link_music",
    "jbl_link_portable",
    "quinglong",
];

#[derive(Parser)]
#[command(about = "YAM v2 package registry")]
struct Cli {
    #[arg(long, env = "YAMREG_ROOT", default_value = "./yamreg-data")]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[arg(long, env = "YAMREG_SIGNING_KEY")]
        signing_key: String,
        #[arg(long, env = "YAMREG_GITHUB_CLIENT_ID")]
        github_client_id: String,
        #[arg(long, env = "YAMREG_GITHUB_CLIENT_SECRET")]
        github_client_secret: String,
        #[arg(long, env = "YAMREG_GITHUB_REDIRECT_URL")]
        github_redirect_url: String,
        /// Comma-separated GitHub logins allowed to access /moderation.
        #[arg(long, env = "YAMREG_ADMIN_GITHUB_LOGINS", value_delimiter = ',')]
        admin_github_logins: Vec<String>,
        /// Mark session cookies Secure (disable only for local HTTP development).
        #[arg(long, env = "YAMREG_COOKIE_SECURE", default_value_t = true)]
        cookie_secure: bool,
    },
    /// Register an Ed25519 author key for a namespace. This is an operator action.
    AddNamespace {
        namespace: String,
        key: String,
        /// GitHub login of the profile permitted to issue tokens for this namespace.
        #[arg(long)]
        owner_github: Option<String>,
    },
    /// Make a published version unavailable and include it in the signed indexes.
    Revoke {
        name: String,
        version: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Recreate static metadata after an offline database operation.
    Reindex {
        #[arg(long, env = "YAMREG_SIGNING_KEY")]
        signing_key: String,
    },
}

#[derive(Clone)]
struct App {
    root: PathBuf,
    db: Arc<Mutex<Connection>>,
    signer: SigningKey,
    admins: Arc<HashSet<String>>,
    cookie_secure: bool,
    github: GitHubOAuth,
}
#[derive(Clone)]
struct GitHubOAuth {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    fs::create_dir_all(cli.root.join("objects/sha256"))?;
    fs::create_dir_all(cli.root.join("public/v2"))?;
    let db = Connection::open(cli.root.join("registry.sqlite3"))?;
    setup_db(&db)?;
    match cli.command {
        Command::AddNamespace {
            namespace,
            key,
            owner_github,
        } => {
            validate_namespace(&namespace)?;
            let key = parse_public_key(&key)?;
            db.execute("INSERT INTO namespaces(namespace, author_key) VALUES (?1,?2) ON CONFLICT(namespace) DO UPDATE SET author_key=excluded.author_key", params![namespace, B64.encode(key.as_bytes())])?;
            if let Some(login) = owner_github {
                let login = normalize_github_login(&login)?;
                let user_id: i64 = db
                    .query_row(
                        "SELECT id FROM users WHERE github_login=?1",
                        [&login],
                        |row| row.get(0),
                    )
                    .context("GitHub user has not signed in yet")?;
                db.execute("INSERT INTO namespace_owners(namespace,user_id) VALUES(?1,?2) ON CONFLICT(namespace) DO UPDATE SET user_id=excluded.user_id", params![namespace,user_id])?;
            }
        }
        Command::Revoke {
            name,
            version,
            reason,
        } => {
            validate_name(&name)?;
            Version::parse(&version)?;
            db.execute("INSERT INTO revocations(name, version, reason, revoked_at) VALUES(?1,?2,?3,datetime('now')) ON CONFLICT(name,version) DO UPDATE SET reason=excluded.reason, revoked_at=excluded.revoked_at", params![name, version, reason])?;
            eprintln!("revocation saved; run `yamreg reindex --signing-key ...` to publish it");
        }
        Command::Reindex { signing_key } => rebuild_indexes(&App {
            root: cli.root,
            db: Arc::new(Mutex::new(db)),
            signer: parse_signing_key(&signing_key)?,
            admins: Arc::new(HashSet::new()),
            cookie_secure: true,
            github: GitHubOAuth {
                client_id: String::new(),
                client_secret: String::new(),
                redirect_url: String::new(),
                client: reqwest::Client::new(),
            },
        })?,
        Command::Serve {
            bind,
            signing_key,
            github_client_id,
            github_client_secret,
            github_redirect_url,
            admin_github_logins,
            cookie_secure,
        } => {
            if !github_redirect_url.starts_with("https://") {
                bail!("YAMREG_GITHUB_REDIRECT_URL must use HTTPS")
            }
            let github = GitHubOAuth {
                client_id: github_client_id,
                client_secret: github_client_secret,
                redirect_url: github_redirect_url,
                client: reqwest::Client::builder()
                    .user_agent("yamreg/0.1 GitHub OAuth")
                    .build()?,
            };
            let app = App {
                root: cli.root,
                db: Arc::new(Mutex::new(db)),
                signer: parse_signing_key(&signing_key)?,
                admins: Arc::new(
                    admin_github_logins
                        .into_iter()
                        .filter_map(|login| normalize_github_login(&login).ok())
                        .collect(),
                ),
                cookie_secure,
                github,
            };
            rebuild_indexes(&app)?;
            info!(%bind, "yamreg listening");
            let router = Router::new()
                .route("/", get(home))
                .route("/packages/:namespace/:package", get(package_page))
                .route("/moderation", get(moderation_page))
                .route("/assets/icons.svg", get(icon_sprite))
                .route("/assets/star.svg", get(star_icon))
                .route("/assets/star-filled.svg", get(star_filled_icon))
                .route("/api/v2", get(api_info))
                .route("/api/v2/health", get(health))
                .route("/api/v2/auth/github", get(github_login))
                .route("/api/v2/auth/github/callback", get(github_callback))
                .route("/api/v2/auth/me", get(current_user))
                .route("/api/v2/auth/logout", post(logout))
                .route("/api/v2/profile", get(profile))
                .route("/api/v2/profile/namespaces", post(claim_namespace))
                .route("/api/v2/profile/tokens", post(create_publish_token))
                .route("/api/v2/profile/tokens/:id", delete(revoke_publish_token))
                .route("/api/v2/packages/:namespace/:package/star", get(star_status).post(star_package).delete(unstar_package))
                .route("/api/v2/moderation/overview", get(moderation_overview))
                .route(
                    "/api/v2/moderation/packages/withdraw",
                    post(withdraw_package),
                )
                .route("/api/v2/moderation/users/ban", post(ban_user))
                .route("/api/v2/moderation/users/unban", post(unban_user))
                .route("/api/v2/upload", post(upload))
                .route("/v2/*path", get(static_file))
                .with_state(app)
                // Uploads are intentionally capped in upload_inner too. This
                // layer stops oversized requests before their body is buffered.
                .layer(DefaultBodyLimit::max(MAX_ARTIFACT_BYTES))
                .layer(SetResponseHeaderLayer::overriding(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                ))
                .layer(SetResponseHeaderLayer::overriding(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ));
            axum::serve(tokio::net::TcpListener::bind(bind).await?, router).await?;
        }
    }
    Ok(())
}

async fn home() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}
async fn package_page() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}
async fn moderation_page() -> Html<&'static str> {
    Html(include_str!("../web/moderation.html"))
}
async fn api_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "YAM Registry API",
        "version": 2,
        "registry_index": "/v2/index.json",
        "health": "/api/v2/health",
        "authentication": "/api/v2/auth/github"
    }))
}
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "service": "yamreg", "time": chrono_now()}))
}
async fn icon_sprite() -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        include_str!("../web/assets/icons.svg"),
    )
        .into_response()
}
async fn star_icon() -> Response {
    svg_asset(include_str!("../web/assets/star.svg"))
}
async fn star_filled_icon() -> Response {
    svg_asset(include_str!("../web/assets/star-filled.svg"))
}
fn svg_asset(body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        body,
    )
        .into_response()
}

fn setup_db(db: &Connection) -> Result<()> {
    db.execute_batch("PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS namespaces(namespace TEXT PRIMARY KEY, author_key TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS artifacts(name TEXT NOT NULL, version TEXT NOT NULL, target TEXT NOT NULL, arch TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE, size INTEGER NOT NULL, manifest TEXT NOT NULL, author_key TEXT NOT NULL, author_signature TEXT NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(name,version,target));
      CREATE TABLE IF NOT EXISTS revocations(name TEXT NOT NULL, version TEXT NOT NULL, reason TEXT, revoked_at TEXT NOT NULL, PRIMARY KEY(name,version));
      CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS namespace_owners(namespace TEXT PRIMARY KEY REFERENCES namespaces(namespace) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
      CREATE TABLE IF NOT EXISTS publish_tokens(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, namespace TEXT NOT NULL REFERENCES namespaces(namespace) ON DELETE CASCADE, label TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT);
       CREATE TABLE IF NOT EXISTS oauth_states(state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
       CREATE TABLE IF NOT EXISTS package_stars(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(user_id,name));
      CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS user_bans(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, reason TEXT NOT NULL, banned_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS moderation_events(id INTEGER PRIMARY KEY, admin_email TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL);
       CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);")?;
    let columns = db
        .prepare("PRAGMA table_info(users)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    if !columns.contains("github_id") {
        db.execute("ALTER TABLE users ADD COLUMN github_id TEXT", [])?;
    }
    if !columns.contains("github_login") {
        db.execute("ALTER TABLE users ADD COLUMN github_login TEXT", [])?;
    }
    if !columns.contains("github_created_at") {
        db.execute("ALTER TABLE users ADD COLUMN github_created_at TEXT", [])?;
    }
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_github_id ON users(github_id) WHERE github_id IS NOT NULL", [])?;
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_github_login ON users(github_login) WHERE github_login IS NOT NULL", [])?;
    Ok(())
}

#[derive(Serialize)]
struct AuthUser {
    login: String,
}
#[derive(Serialize)]
struct ProfileToken {
    id: i64,
    namespace: String,
    label: String,
    created_at: String,
    last_used_at: Option<String>,
}
#[derive(Serialize)]
struct Profile {
    login: String,
    namespaces: Vec<String>,
    tokens: Vec<ProfileToken>,
}
#[derive(Deserialize)]
struct CreateTokenRequest {
    namespace: String,
    label: String,
}
#[derive(Deserialize)]
struct ClaimNamespaceRequest {
    namespace: String,
    author_key: String,
}
#[derive(Serialize)]
struct CreatedToken {
    token: String,
    id: i64,
}
#[derive(Deserialize)]
struct ModerationPackageRequest {
    name: String,
    version: String,
    reason: String,
}
#[derive(Deserialize)]
struct ModerationUserRequest {
    login: String,
    reason: String,
}
#[derive(Serialize)]
struct ModerationOverview {
    packages: Vec<serde_json::Value>,
    users: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
struct PackageRoute {
    namespace: String,
    package: String,
}
#[derive(Serialize)]
struct StarResult {
    starred: bool,
    stars: i64,
}

#[derive(Deserialize)]
struct GitHubCallback {
    code: String,
    state: String,
}
#[derive(Deserialize)]
struct GitHubToken {
    access_token: String,
}
#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    created_at: String,
}

async fn github_login(State(app): State<App>) -> Response {
    match github_login_inner(&app) {
        Ok((state, url)) => (
            [(
                header::SET_COOKIE,
                oauth_state_cookie(&app, &state, "Max-Age=600"),
            )],
            Redirect::temporary(&url),
        )
            .into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
fn github_login_inner(app: &App) -> Result<(String, String)> {
    let state = session_token();
    let now = unix_time()?;
    let db = app.db.lock().unwrap();
    db.execute("DELETE FROM oauth_states WHERE expires_at < ?1", [now])?;
    db.execute(
        "INSERT INTO oauth_states(state_hash,expires_at) VALUES(?1,?2)",
        params![hash_session(&state), now + 600],
    )?;
    Ok((
        state.clone(),
        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
            app.github.client_id,
            urlencoding::encode(&app.github.redirect_url),
            state
        ),
    ))
}
async fn github_callback(
    State(app): State<App>,
    headers: HeaderMap,
    Query(callback): Query<GitHubCallback>,
) -> Response {
    match github_callback_inner(&app, &headers, callback).await {
        Ok((_login, token)) => (
            AppendHeaders([
                (
                    header::SET_COOKIE,
                    session_cookie(&app, &token, "Max-Age=2592000"),
                ),
                (
                    header::SET_COOKIE,
                    oauth_state_cookie(&app, "", "Max-Age=0"),
                ),
            ]),
            Redirect::temporary("/?signed-in=github"),
        )
            .into_response(),
        Err(error) => {
            warn!(%error, "GitHub OAuth rejected");
            (StatusCode::UNAUTHORIZED, error.to_string()).into_response()
        }
    }
}
async fn github_callback_inner(
    app: &App,
    headers: &HeaderMap,
    callback: GitHubCallback,
) -> Result<(String, String)> {
    if callback.code.is_empty() || callback.code.len() > 256 || callback.state.len() > 128 {
        bail!("некорректный OAuth callback")
    }
    if cookie_value(headers, "yamreg_oauth_state").as_deref() != Some(callback.state.as_str()) {
        bail!("OAuth state does not match this browser")
    }
    let now = unix_time()?;
    let state_hash = hash_session(&callback.state);
    {
        let db = app.db.lock().unwrap();
        let used = db.execute(
            "DELETE FROM oauth_states WHERE state_hash=?1 AND expires_at>=?2",
            params![state_hash, now],
        )?;
        if used != 1 {
            bail!("OAuth session expired; start GitHub login again")
        }
    }
    let token = app
        .github
        .client
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", app.github.client_id.as_str()),
            ("client_secret", app.github.client_secret.as_str()),
            ("code", callback.code.as_str()),
            ("redirect_uri", app.github.redirect_url.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<GitHubToken>()
        .await?;
    let github = app
        .github
        .client
        .get("https://api.github.com/user")
        .bearer_auth(token.access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?
        .json::<GitHubUser>()
        .await?;
    let login = normalize_github_login(&github.login)?;
    let created = chrono::DateTime::parse_from_rfc3339(&github.created_at)
        .context("GitHub returned invalid account creation date")?
        .with_timezone(&chrono::Utc);
    if chrono::Utc::now() - created < chrono::Duration::days(7) {
        bail!("GitHub account must be at least 7 days old")
    }
    let mut db = app.db.lock().unwrap();
    let tx = db.transaction()?;
    let github_id = github.id.to_string();
    let user_id: Option<i64> = tx
        .query_row(
            "SELECT id FROM users WHERE github_id=?1",
            [&github_id],
            |r| r.get(0),
        )
        .optional()?;
    let user_id = match user_id {
        Some(id) => {
            tx.execute(
                "UPDATE users SET github_login=?1, github_created_at=?2 WHERE id=?3",
                params![login, github.created_at, id],
            )?;
            id
        }
        None => {
            tx.execute("INSERT INTO users(email,created_at,github_id,github_login,github_created_at) VALUES(?1,datetime('now'),?2,?3,?4)", params![format!("github:{}",github.id), github_id, login, github.created_at])?;
            tx.last_insert_rowid()
        }
    };
    let banned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_bans WHERE user_id=?1)",
        [user_id],
        |r| r.get(0),
    )?;
    if banned {
        bail!("GitHub account is blocked")
    }
    let session = session_token();
    tx.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    tx.execute(
        "INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?1,?2,?3,?4)",
        params![hash_session(&session), user_id, now + 2_592_000, now],
    )?;
    tx.commit()?;
    Ok((login, session))
}

async fn current_user(State(app): State<App>, headers: HeaderMap) -> Response {
    match session_user(&app, &headers) {
        Ok(Some(login)) => Json(AuthUser { login }).into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            warn!(%error, "session lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token_from_headers(&headers)
        && let Err(error) = app.db.lock().unwrap().execute(
            "DELETE FROM sessions WHERE token_hash=?1",
            [hash_session(&token)],
        )
    {
        warn!(%error, "session logout failed");
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session_cookie(&app, "", "Max-Age=0"))],
    )
        .into_response()
}
fn session_cookie(app: &App, token: &str, lifetime: &str) -> String {
    let secure = if app.cookie_secure { "; Secure" } else { "" };
    format!("yamreg_session={token}; Path=/; HttpOnly; SameSite=Lax; {lifetime}{secure}")
}
fn oauth_state_cookie(app: &App, state: &str, lifetime: &str) -> String {
    let secure = if app.cookie_secure { "; Secure" } else { "" };
    format!(
        "yamreg_oauth_state={state}; Path=/api/v2/auth/github; HttpOnly; SameSite=Lax; {lifetime}{secure}"
    )
}

async fn profile(State(app): State<App>, headers: HeaderMap) -> Response {
    match profile_inner(&app, &headers) {
        Ok(Some(profile)) => Json(profile).into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => {
            warn!(%error, "profile lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
fn profile_inner(app: &App, headers: &HeaderMap) -> Result<Option<Profile>> {
    let Some(login) = session_user(app, headers)? else {
        return Ok(None);
    };
    let db = app.db.lock().unwrap();
    let user_id: i64 = db.query_row(
        "SELECT id FROM users WHERE github_login=?1",
        [&login],
        |row| row.get(0),
    )?;
    let namespaces = db
        .prepare("SELECT namespace FROM namespace_owners WHERE user_id=?1 ORDER BY namespace")?
        .query_map([user_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    let tokens = db.prepare("SELECT id,namespace,label,created_at,last_used_at FROM publish_tokens WHERE user_id=?1 AND revoked_at IS NULL ORDER BY id DESC")?.query_map([user_id], |row| Ok(ProfileToken { id:row.get(0)?, namespace:row.get(1)?, label:row.get(2)?, created_at:row.get(3)?, last_used_at:row.get(4)? }))?.collect::<rusqlite::Result<Vec<ProfileToken>>>()?;
    Ok(Some(Profile {
        login,
        namespaces,
        tokens,
    }))
}
async fn create_publish_token(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<CreateTokenRequest>,
) -> Response {
    match create_publish_token_inner(&app, &headers, request) {
        Ok(Some(token)) => (StatusCode::CREATED, Json(token)).into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
fn create_publish_token_inner(
    app: &App,
    headers: &HeaderMap,
    request: CreateTokenRequest,
) -> Result<Option<CreatedToken>> {
    validate_namespace(&request.namespace)?;
    let label = request.label.trim();
    if label.is_empty() || label.len() > 64 {
        bail!("имя токена должно содержать от 1 до 64 символов");
    }
    let Some(login) = session_user(app, headers)? else {
        return Ok(None);
    };
    let token = format!("yamreg_pat_{}", session_token());
    let db = app.db.lock().unwrap();
    let user_id: i64 = db.query_row(
        "SELECT id FROM users WHERE github_login=?1",
        [&login],
        |row| row.get(0),
    )?;
    let owned: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_owners WHERE namespace=?1 AND user_id=?2)",
        params![request.namespace, user_id],
        |row| row.get(0),
    )?;
    if !owned {
        bail!("у профиля нет прав на namespace {}", request.namespace);
    }
    db.execute("INSERT INTO publish_tokens(user_id,namespace,label,token_hash,created_at) VALUES(?1,?2,?3,?4,datetime('now'))", params![user_id,request.namespace,label,hash_session(&token)])?;
    Ok(Some(CreatedToken {
        token,
        id: db.last_insert_rowid(),
    }))
}
async fn claim_namespace(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ClaimNamespaceRequest>,
) -> Response {
    match claim_namespace_inner(&app, &headers, request) {
        Ok(Some(())) => StatusCode::CREATED.into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
fn claim_namespace_inner(
    app: &App,
    headers: &HeaderMap,
    request: ClaimNamespaceRequest,
) -> Result<Option<()>> {
    validate_namespace(&request.namespace)?;
    if request.namespace == "yam" {
        bail!("namespace yam зарезервирован");
    }
    let key = parse_public_key(&request.author_key)?;
    let Some(login) = session_user(app, headers)? else {
        return Ok(None);
    };
    let mut db = app.db.lock().unwrap();
    let user_id: i64 = db.query_row(
        "SELECT id FROM users WHERE github_login=?1",
        [&login],
        |row| row.get(0),
    )?;
    let transaction = db.transaction()?;
    let namespace_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM namespace_owners WHERE user_id=?1",
        [user_id],
        |row| row.get(0),
    )?;
    if namespace_count >= MAX_NAMESPACES_PER_USER {
        bail!("достигнут лимит: не более {MAX_NAMESPACES_PER_USER} namespace на аккаунт");
    }
    let inserted = transaction.execute(
        "INSERT INTO namespaces(namespace,author_key) VALUES(?1,?2) ON CONFLICT(namespace) DO NOTHING",
        params![request.namespace, B64.encode(key.as_bytes())],
    )?;
    if inserted == 0 {
        bail!("namespace {} уже занят", request.namespace);
    }
    transaction.execute(
        "INSERT INTO namespace_owners(namespace,user_id) VALUES(?1,?2)",
        params![request.namespace, user_id],
    )?;
    transaction.commit()?;
    Ok(Some(()))
}
async fn star_package(
    State(app): State<App>,
    headers: HeaderMap,
    Path(route): Path<PackageRoute>,
) -> Response {
    match set_package_star(&app, &headers, route, true) {
        Ok(Some(result)) => Json(result).into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
async fn star_status(
    State(app): State<App>,
    headers: HeaderMap,
    Path(route): Path<PackageRoute>,
) -> Response {
    let result = (|| -> Result<StarResult> {
        let name = format!("{}/{}", route.namespace, route.package);
        validate_name(&name)?;
        let login = session_user(&app, &headers)?;
        let db = app.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE name=?1)",
            [&name],
            |row| row.get(0),
        )?;
        if !exists {
            bail!("package not found")
        }
        let stars = db.query_row(
            "SELECT COUNT(*) FROM package_stars WHERE name=?1",
            [&name],
            |row| row.get(0),
        )?;
        let starred = match login {
            Some(login) => db.query_row("SELECT EXISTS(SELECT 1 FROM package_stars JOIN users ON users.id=package_stars.user_id WHERE users.github_login=?1 AND package_stars.name=?2)", params![login, name], |row| row.get(0))?,
            None => false,
        };
        Ok(StarResult { starred, stars })
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    }
}
async fn unstar_package(
    State(app): State<App>,
    headers: HeaderMap,
    Path(route): Path<PackageRoute>,
) -> Response {
    match set_package_star(&app, &headers, route, false) {
        Ok(Some(result)) => Json(result).into_response(),
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
fn set_package_star(
    app: &App,
    headers: &HeaderMap,
    route: PackageRoute,
    starred: bool,
) -> Result<Option<StarResult>> {
    let name = format!("{}/{}", route.namespace, route.package);
    validate_name(&name)?;
    let Some(login) = session_user(app, headers)? else {
        return Ok(None);
    };
    let changed;
    let stars;
    {
        let db = app.db.lock().unwrap();
        let user_id: i64 = db.query_row(
            "SELECT id FROM users WHERE github_login=?1",
            [&login],
            |row| row.get(0),
        )?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE name=?1)",
            [&name],
            |row| row.get(0),
        )?;
        if !exists {
            bail!("package not found")
        }
        changed = if starred {
            db.execute("INSERT INTO package_stars(user_id,name,created_at) VALUES(?1,?2,datetime('now')) ON CONFLICT(user_id,name) DO NOTHING", params![user_id, name])? > 0
        } else {
            db.execute(
                "DELETE FROM package_stars WHERE user_id=?1 AND name=?2",
                params![user_id, name],
            )? > 0
        };
        stars = db.query_row(
            "SELECT COUNT(*) FROM package_stars WHERE name=?1",
            [&name],
            |row| row.get(0),
        )?;
    }
    if changed {
        rebuild_indexes(app)?;
    }
    Ok(Some(StarResult { starred, stars }))
}
async fn revoke_publish_token(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    match session_user(&app, &headers) {
        Ok(Some(login)) => {
            let result = (|| -> Result<()> {
                let db = app.db.lock().unwrap();
                let user_id: i64 =
                    db.query_row("SELECT id FROM users WHERE github_login=?1", [login], |r| {
                        r.get(0)
                    })?;
                let changed=db.execute("UPDATE publish_tokens SET revoked_at=datetime('now') WHERE id=?1 AND user_id=?2 AND revoked_at IS NULL",params![id,user_id])?;
                if changed == 0 {
                    bail!("токен не найден")
                }
                Ok(())
            })();
            match result {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
            }
        }
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn moderator_login(app: &App, headers: &HeaderMap) -> Result<String> {
    let login = session_user(app, headers)?.context("войдите в профиль")?;
    if !app.admins.contains(&login) {
        bail!("недостаточно прав модератора");
    }
    Ok(login)
}
async fn moderation_overview(State(app): State<App>, headers: HeaderMap) -> Response {
    match moderation_overview_inner(&app, &headers) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::FORBIDDEN, error.to_string()).into_response(),
    }
}
fn moderation_overview_inner(app: &App, headers: &HeaderMap) -> Result<ModerationOverview> {
    moderator_login(app, headers)?;
    let db = app.db.lock().unwrap();
    let packages = db.prepare("SELECT name,version,reason,revoked_at FROM revocations ORDER BY revoked_at DESC")?.query_map([], |r| Ok(serde_json::json!({"name":r.get::<_,String>(0)?,"version":r.get::<_,String>(1)?,"reason":r.get::<_,Option<String>>(2)?,"at":r.get::<_,String>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let users = db.prepare("SELECT users.github_login,user_bans.reason,user_bans.banned_at FROM user_bans JOIN users ON users.id=user_bans.user_id WHERE users.github_login IS NOT NULL ORDER BY user_bans.banned_at DESC")?.query_map([], |r| Ok(serde_json::json!({"login":r.get::<_,String>(0)?,"reason":r.get::<_,String>(1)?,"at":r.get::<_,String>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ModerationOverview { packages, users })
}
async fn withdraw_package(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ModerationPackageRequest>,
) -> Response {
    let result = (|| -> Result<()> {
        let admin = moderator_login(&app, &headers)?;
        validate_name(&request.name)?;
        Version::parse(&request.version)?;
        let reason = request.reason.trim();
        if reason.is_empty() {
            bail!("укажите причину")
        }
        {
            let db = app.db.lock().unwrap();
            db.execute("INSERT INTO revocations(name,version,reason,revoked_at) VALUES(?1,?2,?3,datetime('now')) ON CONFLICT(name,version) DO UPDATE SET reason=excluded.reason,revoked_at=excluded.revoked_at",params![request.name,request.version,reason])?;
            db.execute("INSERT INTO moderation_events(admin_email,action,subject,reason,created_at) VALUES(?1,'withdraw_package',?2,?3,datetime('now'))",params![admin,format!("{}@{}",request.name,request.version),reason])?;
        }
        rebuild_indexes(&app)?;
        Ok(())
    })();
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
async fn ban_user(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ModerationUserRequest>,
) -> Response {
    moderate_user(&app, &headers, request, true).into_response()
}
async fn unban_user(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ModerationUserRequest>,
) -> Response {
    moderate_user(&app, &headers, request, false).into_response()
}
fn moderate_user(
    app: &App,
    headers: &HeaderMap,
    request: ModerationUserRequest,
    ban: bool,
) -> StatusCode {
    let result = (|| -> Result<()> {
        let admin = moderator_login(app, headers)?;
        let login = normalize_github_login(&request.login)?;
        let reason = request.reason.trim();
        if ban && reason.is_empty() {
            bail!("укажите причину")
        };
        let db = app.db.lock().unwrap();
        let user_id: i64 = db
            .query_row(
                "SELECT id FROM users WHERE github_login=?1",
                [&login],
                |r| r.get(0),
            )
            .context("пользователь не найден")?;
        if ban {
            db.execute("INSERT INTO user_bans(user_id,reason,banned_at) VALUES(?1,?2,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason,banned_at=excluded.banned_at",params![user_id,reason])?;
            db.execute("DELETE FROM sessions WHERE user_id=?1", [user_id])?;
        } else {
            db.execute("DELETE FROM user_bans WHERE user_id=?1", [user_id])?;
        }
        db.execute("INSERT INTO moderation_events(admin_email,action,subject,reason,created_at) VALUES(?1,?2,?3,?4,datetime('now'))",params![admin,if ban{"ban_user"}else{"unban_user"},login,reason])?;
        Ok(())
    })();
    if result.is_ok() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn session_user(app: &App, headers: &HeaderMap) -> Result<Option<String>> {
    let Some(token) = session_token_from_headers(headers) else {
        return Ok(None);
    };
    let now = unix_time()?;
    let db = app.db.lock().unwrap();
    db.query_row("SELECT users.github_login FROM sessions JOIN users ON users.id=sessions.user_id LEFT JOIN user_bans ON user_bans.user_id=users.id WHERE sessions.token_hash=?1 AND sessions.expires_at>=?2 AND user_bans.user_id IS NULL AND users.github_id IS NOT NULL", params![hash_session(&token),now], |r| r.get(0)).optional().map_err(Into::into)
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, "yamreg_session")
}
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|value| {
            value
                .trim()
                .strip_prefix(&format!("{name}="))
                .map(str::to_owned)
        })
}
fn normalize_github_login(raw: &str) -> Result<String> {
    let login = raw.trim().to_lowercase();
    if login.is_empty()
        || login.len() > 39
        || login.starts_with('-')
        || login.ends_with('-')
        || !login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("invalid GitHub login");
    }
    Ok(login)
}
fn unix_time() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64)
}
fn hash_session(token: &str) -> String {
    hex::encode(Sha256::digest(token))
}
fn session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct Manifest {
    name: String,
    version: String,
    license: String,
    description: String,
    #[serde(default)]
    homepage: Option<String>,
    target: String,
    arch: String,
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default)]
    recommends: Vec<String>,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    conflicts: Vec<String>,
    #[serde(default)]
    replaces: Vec<String>,
    files_sha256: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct UploadHeaders {
    name: String,
    version: String,
    target: String,
    author_key: String,
    author_signature: String,
}

async fn upload(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    match upload_inner(&app, &headers, &body) {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(e) => {
            warn!(error = %e, "upload rejected");
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
    }
}
fn upload_inner(app: &App, headers: &HeaderMap, bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        bail!("artifact exceeds {} byte limit", MAX_ARTIFACT_BYTES);
    }
    let h = UploadHeaders {
        name: header_value(headers, "x-yam-name")?,
        version: header_value(headers, "x-yam-version")?,
        target: header_value(headers, "x-yam-target")?,
        author_key: header_value(headers, "x-yam-author-key")?,
        author_signature: header_value(headers, "x-yam-author-signature")?,
    };
    validate_name(&h.name)?;
    Version::parse(&h.version)?;
    validate_target(&h.target)?;
    let sha = hex::encode(Sha256::digest(bytes));
    let key = parse_public_key(&h.author_key)?;
    let signature = Signature::from_slice(
        &B64.decode(&h.author_signature)
            .context("invalid author signature base64")?,
    )
    .context("invalid author signature")?;
    key.verify(
        upload_message(&h.name, &h.version, &h.target, &sha).as_bytes(),
        &signature,
    )
    .context("author signature does not bind this upload")?;
    let manifest = validate_artifact(bytes)?;
    if manifest.name != h.name || manifest.version != h.version || manifest.target != h.target {
        bail!("signed upload identity does not match MANIFEST.yaml");
    }
    let namespace = h.name.split_once('/').unwrap().0;
    let db = app.db.lock().unwrap();
    let owner: String = db
        .query_row(
            "SELECT author_key FROM namespaces WHERE namespace=?1",
            [namespace],
            |r| r.get(0),
        )
        .context("unknown namespace")?;
    if owner != B64.encode(key.as_bytes()) {
        bail!("author key does not own namespace {namespace}");
    }
    if let Some(token) = bearer_token(headers) {
        let allowed: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM publish_tokens JOIN users ON users.id=publish_tokens.user_id LEFT JOIN user_bans ON user_bans.user_id=users.id WHERE publish_tokens.token_hash=?1 AND publish_tokens.namespace=?2 AND publish_tokens.revoked_at IS NULL AND user_bans.user_id IS NULL)", params![hash_session(&token),namespace], |r| r.get(0))?;
        if !allowed {
            bail!("publish token is invalid, revoked, or has no access to {namespace}");
        }
        db.execute(
            "UPDATE publish_tokens SET last_used_at=datetime('now') WHERE token_hash=?1",
            [hash_session(&token)],
        )?;
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE name=?1 AND version=?2 AND target=?3)",
        params![h.name, h.version, h.target],
        |r| r.get(0),
    )?;
    if exists {
        bail!(
            "artifact identity {}/{}/{} is immutable",
            h.name,
            h.version,
            h.target
        );
    }
    let object = app.root.join("objects/sha256").join(&sha);
    if !object.exists() {
        fs::write(&object, bytes)?;
    }
    let manifest_json = serde_json::to_string(&manifest_to_metadata(&manifest))?;
    db.execute("INSERT INTO artifacts(name,version,target,arch,sha256,size,manifest,author_key,author_signature,published_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,datetime('now'))", params![h.name,h.version,h.target,manifest.arch,sha,bytes.len() as i64,manifest_json,B64.encode(key.as_bytes()),h.author_signature])?;
    drop(db);
    rebuild_indexes(app)?;
    Ok(serde_json::json!({"name": h.name, "version": h.version, "target": h.target, "sha256": sha}))
}
fn header_value(headers: &HeaderMap, name: &str) -> Result<String> {
    Ok(headers
        .get(name)
        .context(format!("missing {name}"))?
        .to_str()?
        .to_owned())
}
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}
fn upload_message(name: &str, version: &str, target: &str, sha: &str) -> String {
    format!("yamreg-upload-v1\n{name}\n{version}\n{target}\n{sha}\n")
}

fn validate_artifact(bytes: &[u8]) -> Result<Manifest> {
    let decoder =
        zstd::stream::read::Decoder::new(Cursor::new(bytes)).context("artifact is not zstd")?;
    let mut archive = tar::Archive::new(decoder);
    let mut manifest = None;
    let mut files = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut unpacked: u64 = 0;
    for entry in archive.entries().context("invalid tar")? {
        let entry = entry?;
        if paths.len() >= MAX_ENTRIES {
            bail!("too many archive entries");
        }
        let path = entry.path()?.into_owned();
        safe_archive_path(&path)?;
        let path = path.to_string_lossy().into_owned();
        if !paths.insert(path.clone()) {
            bail!("duplicate archive path {path}");
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!("archive entry {path} is not a regular file or directory");
        }
        if kind.is_dir() {
            continue;
        }
        unpacked = unpacked
            .checked_add(entry.size())
            .context("archive size overflow")?;
        if unpacked > MAX_UNPACKED_BYTES {
            bail!("unpacked artifact exceeds limit");
        }
        let mut content = Vec::new();
        entry
            .take(MAX_UNPACKED_BYTES + 1)
            .read_to_end(&mut content)?;
        if path == "MANIFEST.yaml" {
            if manifest.is_some() {
                bail!("duplicate MANIFEST.yaml");
            }
            manifest = Some(
                serde_yaml::from_slice::<Manifest>(&content).context("invalid MANIFEST.yaml")?,
            );
        } else if let Some(payload) = path.strip_prefix("files/") {
            if payload.is_empty() {
                bail!("files/ must be a directory");
            }
            files.insert(payload.to_owned(), content);
        } else {
            bail!("unexpected archive file {path}; only MANIFEST.yaml and files/ are allowed");
        }
    }
    let manifest = manifest.context("missing root MANIFEST.yaml")?;
    validate_manifest(&manifest, &files)?;
    Ok(manifest)
}
fn safe_archive_path(path: &FsPath) -> Result<()> {
    if path.is_absolute() || path.as_os_str().is_empty() || path.to_string_lossy().contains('\\') {
        bail!("absolute or empty archive path");
    }
    for c in path.components() {
        if !matches!(c, Component::Normal(_)) {
            bail!("unsafe archive path {}", path.display());
        }
    }
    Ok(())
}
fn validate_manifest(m: &Manifest, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    validate_name(&m.name)?;
    Version::parse(&m.version)?;
    validate_target(&m.target)?;
    if m.license.trim().is_empty() || m.description.trim().is_empty() {
        bail!("manifest license and description are required");
    }
    if let Some(homepage) = &m.homepage
        && !(homepage.starts_with("https://") || homepage.starts_with("http://"))
    {
        bail!("homepage must be HTTP(S)");
    }
    if m.arch.is_empty() {
        bail!("manifest arch is required");
    }
    if files.len() != m.files_sha256.len() {
        bail!("MANIFEST file list does not match archive");
    }
    for (path, expected) in &m.files_sha256 {
        safe_archive_path(FsPath::new(path))?;
        if path.starts_with("files/")
            || expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("invalid payload hash entry {path}");
        }
        let actual = files
            .get(path)
            .context(format!("manifest payload missing: {path}"))?;
        if hex::encode(Sha256::digest(actual)) != *expected {
            bail!("payload hash mismatch: {path}");
        }
    }
    for (path, body) in files {
        if path.starts_with("bin/") {
            validate_binary(path, body, m)?;
        }
    }
    Ok(())
}
fn validate_binary(path: &str, bytes: &[u8], m: &Manifest) -> Result<()> {
    if bytes.starts_with(b"\x7fELF") {
        if m.target == "any" {
            bail!("native binary {path} cannot target any");
        }
        if bytes.len() < 20 {
            bail!("truncated ELF binary {path}");
        }
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        if m.arch == "aarch64" && machine != 183 {
            bail!("binary {path} is not AArch64 ELF");
        }
    } else if !bytes.starts_with(b"#!") {
        bail!("binary payload {path} must be an ELF executable or shebang script");
    }
    Ok(())
}
fn validate_namespace(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 63
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("invalid namespace");
    }
    Ok(())
}
fn validate_name(s: &str) -> Result<()> {
    let (ns, name) = s
        .split_once('/')
        .context("package name must be namespace/name")?;
    validate_namespace(ns)?;
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("invalid package name");
    }
    Ok(())
}
fn validate_target(s: &str) -> Result<()> {
    if s == "any" {
        return Ok(());
    }
    if SUPPORTED_DEVICE_TARGETS.contains(&s) {
        return Ok(());
    }
    bail!("unsupported device target: {s}")
}

#[derive(Serialize, Deserialize)]
struct Meta {
    #[serde(default)]
    summary: String,
    homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recommends: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provides: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    replaces: Vec<String>,
}
fn manifest_to_metadata(m: &Manifest) -> Meta {
    Meta {
        summary: m.description.clone(),
        homepage: m.homepage.clone(),
        depends: m.depends.clone(),
        recommends: m.recommends.clone(),
        provides: m.provides.clone(),
        conflicts: m.conflicts.clone(),
        replaces: m.replaces.clone(),
    }
}

fn rebuild_indexes(app: &App) -> Result<()> {
    let stage = app.root.join(format!(".publish-{}", std::process::id()));
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir_all(stage.join("v2/packages"))?;
    let db = app.db.lock().unwrap();
    let mut packages: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
    let mut stmt = db.prepare("SELECT name,version,target,arch,sha256,size,manifest,author_key,author_signature,published_at FROM artifacts ORDER BY name,version,target")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
        ))
    })?;
    for row in rows {
        let (name, version, target, arch, sha, size, manifest, key, sig, published) = row?;
        let version_data = packages.entry(name.clone()).or_default().entry(version.clone()).or_insert_with(|| serde_json::json!({"published_at":format!("{}Z",published.replace(' ',"T")),"artifacts":{},"author_signatures":{},"depends":[],"recommends":[],"provides":[],"conflicts":[],"replaces":[]}));
        let meta: Meta = serde_json::from_str(&manifest)?;
        let o = version_data.as_object_mut().unwrap();
        for (field, value) in [
            ("depends", serde_json::to_value(meta.depends)?),
            ("recommends", serde_json::to_value(meta.recommends)?),
            ("provides", serde_json::to_value(meta.provides)?),
            ("conflicts", serde_json::to_value(meta.conflicts)?),
            ("replaces", serde_json::to_value(meta.replaces)?),
        ] {
            o.insert(field.to_owned(), value);
        }
        o.insert("summary".into(), serde_json::json!(meta.summary));
        if let Some(homepage) = meta.homepage {
            o.insert("homepage".into(), serde_json::json!(homepage));
        }
        o.get_mut("artifacts").unwrap().as_object_mut().unwrap().insert(target.clone(),serde_json::json!({"arch":arch,"url":format!("packages/{}/{}/{target}.yampkg",name,version),"sha256":sha,"size":size}));
        o.get_mut("author_signatures").unwrap().as_object_mut().unwrap().insert(target,serde_json::json!({"key":format!("ed25519:{key}"),"signature":sig,"message":"yamreg-upload-v1\\n<name>\\n<version>\\n<target>\\n<sha256>\\n"}));
    }
    let revocations = revocations(&db)?;
    let stars = package_star_counts(&db)?;
    drop(stmt);
    drop(db);
    let mut catalogue = Vec::new();
    for (name, versions) in &packages {
        let (ns, pkg) = name.split_once('/').unwrap();
        let dir = stage.join("v2/packages").join(ns).join(pkg);
        fs::create_dir_all(&dir)?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":2,"name":name,"versions":versions,"revoked":revocations.get(name).cloned().unwrap_or_default()}),
        )?;
        signed_write(&dir.join("index.json"), &bytes, &app.signer)?;
        let latest = versions
            .keys()
            .filter_map(|v| Version::parse(v).ok())
            .filter(|v| v.pre.is_empty())
            .max()
            .map(|v| v.to_string());
        let targets: Vec<_> = versions
            .values()
            .flat_map(|v| {
                v["artifacts"]
                    .as_object()
                    .into_iter()
                    .flat_map(|m| m.keys())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .cloned()
            .collect();
        let summary = latest
            .as_ref()
            .and_then(|v| versions.get(v))
            .and_then(|v| v.get("summary"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let homepage = latest
            .as_ref()
            .and_then(|v| versions.get(v))
            .and_then(|v| v.get("homepage"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        catalogue.push(serde_json::json!({"name":name,"summary":summary,"homepage":homepage,"latest":latest,"targets":targets,"stars":stars.get(name).copied().unwrap_or(0)}));
    }
    let bytes = serde_json::to_vec(
        &serde_json::json!({"format":2,"generated_at":chrono_now(),"packages":catalogue,"revoked":revocations}),
    )?;
    signed_write(&stage.join("v2/index.json"), &bytes, &app.signer)?;
    // Artifact URLs are stable hard links to immutable content-addressed objects.
    for (name, versions) in packages {
        let (ns, pkg) = name.split_once('/').unwrap();
        for (version, data) in versions {
            for (target, artifact) in data["artifacts"].as_object().unwrap() {
                let hash = artifact["sha256"].as_str().unwrap();
                let dir = stage.join("v2/packages").join(ns).join(pkg).join(&version);
                fs::create_dir_all(&dir)?;
                fs::hard_link(
                    app.root.join("objects/sha256").join(hash),
                    dir.join(format!("{target}.yampkg")),
                )?;
                fs::write(
                    dir.join(format!("{target}.yampkg.sha256")),
                    format!("{hash}  {target}.yampkg\n"),
                )?;
            }
        }
    }
    let public = app.root.join("public");
    let old = app.root.join(".public-old");
    if old.exists() {
        fs::remove_dir_all(&old)?;
    }
    if public.exists() {
        fs::rename(&public, &old)?;
    }
    fs::rename(&stage, &public)?;
    if old.exists() {
        fs::remove_dir_all(old)?;
    }
    Ok(())
}
fn revocations(db: &Connection) -> Result<BTreeMap<String, Vec<serde_json::Value>>> {
    let mut map = BTreeMap::new();
    let mut s =
        db.prepare("SELECT name,version,reason,revoked_at FROM revocations ORDER BY name,version")?;
    for r in s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (n, v, reason, at) = r?;
        map.entry(n).or_insert_with(Vec::new).push(serde_json::json!({"version":v,"reason":reason,"revoked_at":format!("{}Z",at.replace(' ',"T"))}));
    }
    Ok(map)
}
fn package_star_counts(db: &Connection) -> Result<BTreeMap<String, i64>> {
    let mut counts = BTreeMap::new();
    let mut statement = db.prepare("SELECT name,COUNT(*) FROM package_stars GROUP BY name")?;
    for row in statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })? {
        let (name, count) = row?;
        counts.insert(name, count);
    }
    Ok(counts)
}
fn chrono_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn signed_write(path: &FsPath, bytes: &[u8], key: &SigningKey) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, bytes)?;
    fs::write(
        format!("{}.sig", path.display()),
        B64.encode(key.sign(bytes).to_bytes()),
    )?;
    Ok(())
}
async fn static_file(State(app): State<App>, Path(path): Path<String>) -> Response {
    if path.is_empty()
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let file = app.root.join("public/v2").join(&path);
    match tokio::fs::read(file).await {
        Ok(b) => {
            let content = if path.ends_with(".json") {
                "application/json"
            } else if path.ends_with(".sig") {
                "text/plain"
            } else {
                "application/octet-stream"
            };
            let cache_control = if path.ends_with(".yampkg") {
                "public, max-age=31536000, immutable"
            } else {
                // Indexes and signatures are small and may change after a
                // publish or moderation action. Clients must revalidate them.
                "no-cache"
            };
            (
                [
                    (header::CONTENT_TYPE, content),
                    (header::CACHE_CONTROL, cache_control),
                ],
                b,
            )
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
fn parse_public_key(value: &str) -> Result<VerifyingKey> {
    let raw = value.strip_prefix("ed25519:").unwrap_or(value);
    let bytes = B64.decode(raw)?;
    VerifyingKey::from_bytes(
        &bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?,
    )
    .map_err(Into::into)
}
fn parse_signing_key(value: &str) -> Result<SigningKey> {
    let raw = value.strip_prefix("ed25519:").unwrap_or(value);
    let bytes = B64.decode(raw)?;
    Ok(SigningKey::from_bytes(&bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Ed25519 signing key must be a base64 32-byte seed")
    })?))
}

#[cfg(test)]
mod tests {
    use super::validate_target;

    #[test]
    fn accepts_supported_quasar_devices_and_generic_packages() {
        for target in [
            "any",
            "yandexmicro",
            "plum",
            "yandexplum",
            "chiron",
            "quinglong",
        ] {
            assert!(validate_target(target).is_ok(), "{target}");
        }
    }

    #[test]
    fn rejects_unsupported_and_non_speaker_devices() {
        for target in [
            "goya",
            "yandex_tv",
            "saturn",
            "mike",
            "cherry",
            "unknown-device",
        ] {
            assert!(validate_target(target).is_err(), "{target}");
        }
    }
}
