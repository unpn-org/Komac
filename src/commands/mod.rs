pub mod analyze;
pub mod cleanup;
pub mod complete;
pub mod list_versions;
pub mod new_locale;
pub mod new_version;
pub mod remove_dead_versions;
pub mod remove_version;
pub mod show_version;
pub mod submit;
pub mod sync_fork;
pub mod token;
pub mod update_version;
pub mod utils;

use std::{future::Future, pin::Pin};

use analyze::Analyze;
use clap::Subcommand;
use cleanup::Cleanup;
use complete::Complete;
use list_versions::ListVersions;
use new_locale::NewLocale;
use new_version::NewVersion;
use remove_dead_versions::RemoveDeadVersions;
use remove_version::RemoveVersion;
use show_version::ShowVersion;
use submit::Submit;
use sync_fork::SyncFork;
use token::commands::{TokenArgs, TokenCommands};
use update_version::UpdateVersion;

#[derive(Subcommand)]
pub enum Commands {
    New(Box<NewVersion>),       // Comparatively large so boxed to store on the heap
    NewLocale(Box<NewLocale>),  // Comparatively large so boxed to store on the heap
    Update(Box<UpdateVersion>), // Comparatively large so boxed to store on the heap
    Remove(RemoveVersion),
    Cleanup(Cleanup),
    Token(TokenArgs),
    List(ListVersions),
    Show(ShowVersion),
    Sync(SyncFork),
    Complete(Complete),
    Analyze(Analyze),
    RemoveDeadVersions(RemoveDeadVersions),
    Submit(Submit),
}

impl Commands {
    pub fn run(self) -> Pin<Box<dyn Future<Output = color_eyre::Result<()>>>> {
        match self {
            Self::New(new_version) => Box::pin(new_version.run()),
            Self::NewLocale(new_locale) => Box::pin(new_locale.run()),
            Self::Update(update_version) => Box::pin(update_version.run()),
            Self::Cleanup(cleanup) => Box::pin(cleanup.run()),
            Self::Remove(remove_version) => Box::pin(remove_version.run()),
            Self::Token(token_args) => match token_args.command {
                TokenCommands::Remove(remove_token) => Box::pin(async move { remove_token.run() }),
                TokenCommands::Update(update_token) => Box::pin(update_token.run()),
            },
            Self::List(list_versions) => Box::pin(list_versions.run()),
            Self::Show(show_version) => Box::pin(show_version.run()),
            Self::Sync(sync_fork) => Box::pin(sync_fork.run()),
            Self::Complete(complete) => Box::pin(async move { complete.run() }),
            Self::Analyze(analyse) => Box::pin(async move { analyse.run() }),
            Self::RemoveDeadVersions(remove_dead_versions) => Box::pin(remove_dead_versions.run()),
            Self::Submit(submit) => Box::pin(submit.run()),
        }
    }
}
