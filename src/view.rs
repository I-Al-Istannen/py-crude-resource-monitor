use crate::samples::{read_sample_file, sample_files};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use log::info;
use rust_embed::Embed;
use snafu::{Location, ResultExt, Snafu};
use std::path::PathBuf;
use tower_http::cors::CorsLayer;

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

/// The built frontend, embedded into the binary
#[derive(Embed)]
#[folder = "frontend/dist/"]
pub struct Asset;

pub async fn run_view(output_dir: PathBuf, interface: &str, port: u16) -> Result<(), ViewError> {
    let app = Router::new()
        // nest to ensure the prefix is stripped
        .nest(
            "/view",
            Router::new().route("/{*file}", get(serve_profile_data)),
        )
        .route("/", get(|| async { FrontendStaticFile("index.html") }))
        .route("/{*file}", get(serve_frontend))
        // Only the vite dev server needs to access us cross-origin. Allowing any origin would let
        // every website you visit read your profiles.
        .layer(CorsLayer::new().allow_origin([
            HeaderValue::from_static("http://localhost:5173"),
            HeaderValue::from_static("http://127.0.0.1:5173"),
        ]))
        .with_state(output_dir);

    let listen_address = format!("{interface}:{port}");
    info!("Listening on {listen_address}");
    if interface == "127.0.0.1" || interface == "localhost" {
        info!("Open http://localhost:{port} to view the profile");
    } else {
        info!("This probably resolves to http://localhost:{port}");
    }

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

/// Serves the list of sample files and their content. The frontend gets every file uncompressed,
/// named `<name>.json`, e.g. `42.json`.
async fn serve_profile_data(
    State(profile_data_directory): State<PathBuf>,
    Path(file): Path<String>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let files = sample_files(&profile_data_directory)?;
        if file == "profiles.json" {
            let names = files
                .into_iter()
                .map(|(name, _)| format!("{name}.json"))
                .collect::<Vec<_>>();
            return Ok(Some(Json(names).into_response()));
        }
        // Only serve files from the list, so the path can not point anywhere else
        let Some((_, path)) = files
            .into_iter()
            .find(|(name, _)| file.strip_suffix(".json") == Some(name.as_str()))
        else {
            return Ok(None);
        };
        let content = read_sample_file(&path)?;
        Ok::<_, std::io::Error>(Some(
            ([(header::CONTENT_TYPE, "application/x-ndjson")], content).into_response(),
        ))
    })
    .await;

    match result {
        Ok(Ok(Some(response))) => response,
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
