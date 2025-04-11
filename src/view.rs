use axum::extract::{Request, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use log::info;
use rust_embed::Embed;
use snafu::{Location, ResultExt, Snafu};
use std::path::PathBuf;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

#[derive(Debug, Snafu)]
pub enum ViewError {
    #[snafu(display("Error binding to interface `{interface}` at {location}"))]
    BindToInterface {
        source: std::io::Error,
        interface: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error running webserver at {location}"))]
    Axum {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

#[derive(Embed)]
#[folder = "frontend/dist/"]
struct Asset;

pub async fn run_view(output_dir: PathBuf, interface: &str, port: u16) -> Result<(), ViewError> {
    let app = Router::new()
        // nest to ensure the prefix is stripped
        .nest(
            "/view",
            Router::new().route("/{*file}", get(serve_profile_data)),
        )
        .route("/", get(|| async { FrontendStaticFile("index.html") }))
        .route("/{*file}", get(serve_frontend))
        .layer(CorsLayer::very_permissive())
        .with_state(output_dir);

    let listen_address = format!("{interface}:{port}");
    info!("Listening on {listen_address}");
    info!("This probably resolves to http://localhost:{port}");

    let listener = tokio::net::TcpListener::bind(listen_address.clone())
        .await
        .context(BindToInterfaceSnafu {
            interface: listen_address,
        })?;
    axum::serve(listener, app).await.context(AxumSnafu)?;

    Ok(())
}

async fn serve_frontend(uri: Uri) -> impl IntoResponse {
    FrontendStaticFile(uri.path().trim_start_matches('/').to_string())
}

async fn serve_profile_data(
    State(profile_data_directory): State<PathBuf>,
    req: Request,
) -> Result<Response, String> {
    if req.uri().path() == "/profiles.json" {
        let files = std::fs::read_dir(profile_data_directory)
            .map_err(|_| "error reading data directory")?
            .filter_map(|f| f.ok())
            .filter(|f| f.path().extension().map(|e| e == "json").unwrap_or(false))
            .map(|f| f.path().file_name().unwrap().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        return Ok(Json(files).into_response());
    }
    Ok(ServeDir::new(profile_data_directory)
        .oneshot(req)
        .await
        .map_err(|e| e.to_string())?
        .into_response())
}

pub struct FrontendStaticFile<T>(pub T);

impl<T> IntoResponse for FrontendStaticFile<T>
where
    T: Into<String>,
{
    fn into_response(self) -> Response {
        let path = self.0.into();

        match Asset::get(path.as_str()) {
            Some(content) => {
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
            }
            None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
        }
    }
}
