use crate::{
    AppResult,
    model::{Credentials, CredentialsSummary},
    storage::VaultStorage,
    vault_manager::VaultManager,
};

pub struct App<S: VaultStorage> {
    pub current_screen: CurrentScreen,
    pub vault_manager: VaultManager<S>,
    pub credentials: Vec<CredentialsSummary>,
    pub selected_credential_index: usize,
    pub service_input: String,
    pub username_input: String,
    pub password_input: String,
    pub notes_input: String,
    pub search_input: String,
    pub search_results: Vec<Credentials>,
    pub current_input_field: InputField,
    pub viewed_credential: Option<Credentials>,
    pub show_password: bool,
    pub error_message: String,
}

pub enum CurrentScreen {
    Main,
    Add,
    Edit,
    View,
    Search,
    Error,
    Exiting,
}

#[derive(PartialEq)]
pub enum InputField {
    Service,
    Username,
    Password,
    Notes,
}

impl<S: VaultStorage> App<S> {
    pub fn new(vault_manager: VaultManager<S>) -> AppResult<Self> {
        let mut app = App {
            current_screen: CurrentScreen::Main,
            vault_manager,
            credentials: Vec::new(),
            selected_credential_index: 0,
            service_input: String::new(),
            username_input: String::new(),
            password_input: String::new(),
            notes_input: String::new(),
            search_input: String::new(),
            search_results: Vec::new(),
            current_input_field: InputField::Service,
            viewed_credential: None,
            show_password: false,
            error_message: String::new(),
        };

        app.refresh_credentials()?;
        Ok(app)
    }

    pub fn refresh_credentials(&mut self) -> AppResult<()> {
        self.credentials = self.vault_manager.list_credentials()?;
        if self.selected_credential_index >= self.credentials.len() && !self.credentials.is_empty()
        {
            self.selected_credential_index = self.credentials.len() - 1;
        }
        Ok(())
    }

    pub fn show_error(&mut self, message: &str) {
        self.error_message = message.to_string();
        self.current_screen = CurrentScreen::Error;
    }
}
