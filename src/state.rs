use std::sync::Arc;

use crate::{
    repositories::{
        EmailVerificationRepository, EmailVerificationRepositoryTrait, PasswordResetRepository,
        PasswordResetRepositoryTrait, RefreshTokenRepository, RefreshTokenRepositoryTrait,
        UserRepository, UserRepositoryTrait,
    },
    services::email_services::EmailService,
};

use axum::extract::FromRef;
use sqlx::PgPool;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: Arc<dyn UserRepositoryTrait>,
    pub email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait>,
    pub email_service: Arc<EmailService>,
    pub password_reset_repository: Arc<dyn PasswordResetRepositoryTrait>,
    pub refresh_token_repository: Arc<dyn RefreshTokenRepositoryTrait>,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = PgPool::connect(database_url).await?;

        sqlx::migrate!("./migrations").run(&db).await?;

        let user_repository: Arc<dyn UserRepositoryTrait> =
            Arc::new(UserRepository::new(db.clone()));
        let email_verification_repository: Arc<dyn EmailVerificationRepositoryTrait> =
            Arc::new(EmailVerificationRepository::new(db.clone()));

        let password_reset_repository: Arc<dyn PasswordResetRepositoryTrait> =
            Arc::new(PasswordResetRepository::new(db.clone()));
        let refresh_token_repository: Arc<dyn RefreshTokenRepositoryTrait> =
            Arc::new(RefreshTokenRepository::new(db.clone()));

        println!("Initializing email service...");
        let email_service = match EmailService::new() {
            Ok(service) => Arc::new(service),
            Err(e) => {
                eprintln!("Failed to initialize email service: {}", e);
                eprintln!("Make sure all SMTP env vars are set in .env");
                panic!("Email service initialization failed");
            }
        };

        Ok(Self {
            db,
            user_repository,
            email_verification_repository,
            email_service,
            password_reset_repository,
            refresh_token_repository,
        })
    }
}
