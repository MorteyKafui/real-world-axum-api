use std::env;

use axum::{Router, routing::get};

mod handlers;
mod state;

use handlers::health::health_check;
use state::AppState;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must bet set in .env file");

    let app_state = AppState::new(&database_url)
        .await
        .expect("Failed to connect to database");

    println!("Connected to database successfully");

    let app = Router::new()
        .route("/health", get(health_check))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Server is running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
