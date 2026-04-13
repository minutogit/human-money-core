//! # src/app_service/app_profile_handler.rs
//!
//! Implementiert Operationen zur Verwaltung des Nutzerprofils (Metadata).

use super::{AppService, AppState};
use crate::models::profile::PublicProfile;
use crate::storage::AuthMethod;

impl AppService {
    /// Updates the public profile of the wallet owner.
    ///
    /// The update is followed by an automatic save. To allow this, either an active
    /// session must be present, or a password must be provided.
    pub fn update_public_profile(
        &mut self,
        profile: PublicProfile,
        password: Option<&str>,
    ) -> Result<(), String> {
        // 1. Get auth method (either from session or from provided password)
        let auth = if let Some(pw) = password {
            AuthMethod::Password(pw)
        } else {
            let session_key = self.get_session_key()?;
            AuthMethod::SessionKey(session_key)
        };

        // 2. Update the profile in the wallet
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                ..
            } => {
                // Update internal profile fields
                wallet.profile.first_name = profile.first_name;
                wallet.profile.last_name = profile.last_name;
                wallet.profile.organization = profile.organization;
                wallet.profile.community = profile.community;
                wallet.profile.address = profile.address;
                wallet.profile.gender = profile.gender;
                wallet.profile.email = profile.email;
                wallet.profile.phone = profile.phone;
                wallet.profile.coordinates = profile.coordinates;
                wallet.profile.url = profile.url;
                wallet.profile.service_offer = profile.service_offer;
                wallet.profile.needs = profile.needs;

                // 3. Save the wallet
                wallet.save(storage, identity, &auth).map_err(|e| e.to_string())?;
                Ok(())
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}


