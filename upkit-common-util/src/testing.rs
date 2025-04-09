/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! Testing related utility functions.

/// Initialize the `env` logger crate.
pub fn initialize_env_logger() {
    env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init()
        .map_err(|e| log::trace!("Env logger for testing was probably already initialized: {e:?}"))
        .ok();
}

/// Load a text resource from `{cargo_manifest_dir}/resources/test/{relative_path}`.
///
/// Use `env!("CARGO_MANIFEST_DIR")` as the first parameter.
/// (The main purpose of this function is to be consistent in where test
/// resources are located.)
pub fn load_resource_file_as_string(cargo_manifest_dir: &str, relative_path: &str) -> String {
    let mut file_path = std::path::PathBuf::from(cargo_manifest_dir);
    file_path.push("resources/test");
    file_path.push(relative_path);
    let full_filename = file_path.display().to_string();
    log::trace!("Loading '{full_filename}'.");
    std::fs::read_to_string(file_path)
        .unwrap_or_else(|_| panic!("Missing test data '{full_filename}'."))
}
