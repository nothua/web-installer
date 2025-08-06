#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui::{self};
use std::{fs::File, io::Write, path::PathBuf, process::Command, thread};
use reqwest::blocking::get;
use std::fs;
use std::sync::{Arc, Mutex};
use std::io::Read;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::env;
use sevenz_rust;
use std::time::Instant; // Import Instant for time-based repaints

const INSTALLER_NAME: &str = "Example Setup";
const SUBFOLDER_NAME: &str = "example";
const APP_ICON_BYTES: &[u8] = include_bytes!("../icons/logo.png");
const APP_NAME: &str = "Example";
const APP_VERSION: &str = "";
const APP_PUBLISHER: &str = "nothua";
const APP_HELP_LINK: &str = "http://nothua.com/";
const APP_UPDATE_INFO_URL: &str = "";
const APP_SUPPORT_URL: &str = "";
const APP_EXECUTABLE_NAME: &str = "example.exe";
const JSON_FEED_URL: &str = "version.json";

fn get_registry_uninstall_key() -> String {
    format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}", APP_NAME)
}

fn get_install_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(format!(
            "{}\\AppData\\Local\\{}",
            std::env::var("USERPROFILE").unwrap(),
            APP_NAME
        ))
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/opt").join(APP_NAME.to_lowercase())
    }
}

fn check_if_app_installed() -> bool {
    let install_path = get_install_path();
    let main_exe = install_path.join(APP_EXECUTABLE_NAME);
    install_path.exists() && (main_exe.exists())
}

#[cfg(target_os = "windows")]
fn check_process_running(process_name: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("tasklist")
        .arg("/nh")
        .arg("/fo")
        .arg("csv")
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.lines().any(|line| line.contains(process_name))
        },
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn check_process_running(_process_name: &str) -> bool {
    false
}

fn calculate_directory_size(path: &PathBuf) -> Result<u64, std::io::Error> {
    let mut total_size = 0;

    if path.is_file() {
        return Ok(path.metadata()?.len());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();

        if entry_path.is_file() {
            total_size += entry.metadata()?.len();
        } else if entry_path.is_dir() {
            total_size += calculate_directory_size(&entry_path)?;
        }
    }

    Ok(total_size)
}

#[cfg(target_os = "windows")]
fn get_current_date_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let days_since_epoch = now / 86400;
    let days_since_1970 = days_since_epoch;

    let mut year = 1970;
    let mut remaining_days = days_since_1970;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!("{:04}{:02}{:02}", year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(not(target_os = "windows"))]
fn get_current_date_string() -> String {
    "20240101".to_string()
}

fn copy_self_to_install_path(install_path: &PathBuf) -> Result<(), String> {
    let current_exe = env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {}", e))?;

    let destination_path = install_path.join(current_exe.file_name().unwrap());

    if current_exe != destination_path {
        fs::copy(&current_exe, &destination_path)
            .map_err(|e| format!("Failed to copy self to install path: {}", e))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn register_in_windows_registry(install_path: &PathBuf) -> Result<(), String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let (uninstall_key, _) = hkcu
        .create_subkey(get_registry_uninstall_key())
        .map_err(|e| format!("Failed to create registry key: {}", e))?;

    let app_exe_path = install_path.join(APP_EXECUTABLE_NAME);

    let run_silent_vbs_path = install_path.join(format!("{}_run_silent_uninstall.vbs", APP_NAME.to_lowercase()));
    let icon_path = app_exe_path.to_string_lossy().to_string();

    let install_size_kb = calculate_directory_size(install_path).unwrap_or(0) / 1024;

    uninstall_key
        .set_value("DisplayName", &APP_NAME)
        .map_err(|e| format!("Failed to set DisplayName: {}", e))?;

    if !APP_VERSION.is_empty(){
        uninstall_key
            .set_value("DisplayVersion", &APP_VERSION)
            .map_err(|e| format!("Failed to set DisplayVersion: {}", e))?;
    }

    uninstall_key
        .set_value("Publisher", &APP_PUBLISHER)
        .map_err(|e| format!("Failed to set Publisher: {}", e))?;

    uninstall_key
        .set_value("InstallLocation", &install_path.to_string_lossy().as_ref())
        .map_err(|e| format!("Failed to set InstallLocation: {}", e))?;

    uninstall_key
        .set_value(
            "UninstallString",
            &format!("wscript.exe //B \"{}\"", run_silent_vbs_path.to_string_lossy()),
        )
        .map_err(|e| format!("Failed to set UninstallString: {}", e))?;

    uninstall_key
        .set_value(
            "QuietUninstallString",
            &format!("wscript.exe //B \"{}\"", run_silent_vbs_path.to_string_lossy()),
        )
        .map_err(|e| format!("Failed to set QuietUninstallString: {}", e))?;

    uninstall_key
        .set_value("DisplayIcon", &icon_path)
        .map_err(|e| format!("Failed to set DisplayIcon: {}", e))?;

    uninstall_key
        .set_value("EstimatedSize", &(install_size_kb as u32))
        .map_err(|e| format!("Failed to set EstimatedSize: {}", e))?;

    if !APP_HELP_LINK.is_empty(){
        uninstall_key
            .set_value("HelpLink", &APP_HELP_LINK)
            .map_err(|e| format!("Failed to set HelpLink: {}", e))?;
    }
    if !APP_UPDATE_INFO_URL.is_empty(){
        uninstall_key
            .set_value("URLUpdateInfo", &APP_UPDATE_INFO_URL)
            .map_err(|e| format!("Failed to set URLUpdateInfo: {}", e))?;
    }
    if !APP_SUPPORT_URL.is_empty(){
        uninstall_key
            .set_value("SupportLink", &APP_SUPPORT_URL)
            .map_err(|e| format!("Failed to set SupportLink: {}", e))?;
    }

    let install_date = get_current_date_string();
    uninstall_key
        .set_value("InstallDate", &install_date)
        .map_err(|e| format!("Failed to set InstallDate: {}", e))?;

    uninstall_key
        .set_value("NoModify", &1u32)
        .map_err(|e| format!("Failed to set NoModify: {}", e))?;

    uninstall_key
        .set_value("NoRepair", &1u32)
        .map_err(|e| format!("Failed to set NoRepair: {}", e))?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn register_in_windows_registry(_install_path: &PathBuf) -> Result<(), String> {
    Ok(())
}

fn create_uninstaller(install_path: &PathBuf) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let app_name_lower = APP_NAME.to_lowercase();
        let uninstaller_cmd_path = install_path.join(format!("{}_uninstall.cmd", app_name_lower));
        let run_silent_vbs_path = install_path.join(format!("{}_run_silent_uninstall.vbs", app_name_lower));
        let show_message_vbs_path = install_path.join(format!("{}_uninstall_success_msg.vbs", app_name_lower));
        let confirm_message_vbs_path = install_path.join(format!("{}_uninstall_confirm_msg.vbs", app_name_lower));
        let cleanup_cmd_path = install_path.join(format!("{}_uninstall_cleanup.cmd", app_name_lower));

        let confirm_message_vbs_content = format!(
            r#"Dim objShell, intRet
Set objShell = CreateObject("WScript.Shell")
intRet = objShell.Popup("Are you sure you want to completely remove {} and all of its components?", 0, "Confirm Uninstallation", 4 + 32)
If intRet = 7 Then
    WScript.Quit 1
Else
    WScript.Quit 0
End If"#,
            APP_NAME
        );
        fs::write(&confirm_message_vbs_path, confirm_message_vbs_content)
            .map_err(|e| format!("Failed to create VBS confirmation script: {}", e))?;

        let uninstaller_script_content = format!(
            r#"@echo off
            title Uninstalling {app_name}
            echo Uninstalling {app_name}...

            call wscript.exe //nologo "{confirm_message_vbs}"
            if %errorlevel% NEQ 0 (
                echo Uninstallation cancelled by user.
                exit /b 1
            )

            taskkill /f /im "{exe_name}" >nul 2>&1
            timeout /t 2 /nobreak >nul

            del "%USERPROFILE%\\Desktop\\{app_name}.lnk" >nul 2>&1

            reg delete "HKEY_CURRENT_USER\{registry_key}" /f >nul 2>&1

            call wscript.exe "{show_message_vbs}"

            call "{cleanup_cmd}"
            exit
            "#,
            app_name = APP_NAME,
            exe_name = APP_EXECUTABLE_NAME,
            registry_key = get_registry_uninstall_key(),
            confirm_message_vbs = confirm_message_vbs_path.to_string_lossy(),
            show_message_vbs = show_message_vbs_path.to_string_lossy(),
            cleanup_cmd = cleanup_cmd_path.to_string_lossy()
        );

        fs::write(&uninstaller_cmd_path, uninstaller_script_content)
            .map_err(|e| format!("Failed to create uninstaller batch: {}", e))?;

        let uninstaller_cmd_path_str = uninstaller_cmd_path.to_string_lossy();
        let run_silent_vbs_content = format!(
            r#"Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd.exe /c " & Chr(34) & "{}" & Chr(34), 0, True"#,
            uninstaller_cmd_path_str.replace("\\", "\\\\")
        );

        fs::write(&run_silent_vbs_path, run_silent_vbs_content)
            .map_err(|e| format!("Failed to create VBS run silent script: {}", e))?;

        let show_message_vbs_content = format!(
            r#"Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Popup "{app_name} has been successfully uninstalled.", 0, "{app_name} Uninstallation", 64"#,
            app_name = APP_NAME
        );

        fs::write(&show_message_vbs_path, show_message_vbs_content)
            .map_err(|e| format!("Failed to create VBS message script: {}", e))?;

        let cleanup_script_content = format!(
            r#"@echo off
            timeout /t 5 /nobreak >nul

            rmdir /s /q "{install_dir}" >nul 2>&1

            del "{uninstaller_cmd}" >nul 2>&1
            del "{run_silent_vbs}" >nul 2>&1
            del "{show_message_vbs}" >nul 2>&1
            del "{confirm_message_vbs}" >nul 2>&1
            
            reg delete "HKEY_CURRENT_USER\\{registry_key}" /f >nul 2>&1

            del "{cleanup_cmd}" >nul 2>&1
            "#,
            install_dir = install_path.to_string_lossy(),
            uninstaller_cmd = uninstaller_cmd_path.to_string_lossy(),
            run_silent_vbs = run_silent_vbs_path.to_string_lossy(),
            show_message_vbs = show_message_vbs_path.to_string_lossy(),
            confirm_message_vbs = confirm_message_vbs_path.to_string_lossy(),
            registry_key = get_registry_uninstall_key(),
            cleanup_cmd = cleanup_cmd_path.to_string_lossy()
        );

        fs::write(&cleanup_cmd_path, cleanup_script_content)
            .map_err(|e| format!("Failed to create cleanup script: {}", e))?;

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Uninstaller creation not implemented for this OS.".to_string())
    }
}

fn create_shortcut(install_path: &PathBuf) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let user_profile = std::env::var("USERPROFILE")
            .map_err(|e| format!("Failed to get USERPROFILE: {}", e))?;

        let app_exe_path = install_path.join(APP_EXECUTABLE_NAME);

        let vbs: String = format!(
            r#"Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{}\\Desktop\\{}.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{}"
oLink.Save"#,
            user_profile,
            APP_NAME,
            app_exe_path.display()
        );

        let vbs_path = std::env::temp_dir().join("shortcut.vbs");
        std::fs::write(&vbs_path, vbs)
            .map_err(|e| format!("Failed to write VBS script: {}", e))?;

        Command::new("wscript")
            .arg(&vbs_path)
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| format!("Failed to spawn wscript: {}", e))?
            .wait()
            .map_err(|e| format!("wscript command failed: {}", e))?;

        let _ = fs::remove_file(&vbs_path);

        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Shortcut creation not implemented for this OS.".to_string())
    }
}

fn launch_app() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let install_path = get_install_path();
        let app_exe_path = install_path.join(APP_EXECUTABLE_NAME);

        if !app_exe_path.exists() {
            return Err(format!("Application executable not found at: {}", app_exe_path.display()));
        }

        Command::new(&app_exe_path)
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| format!("Failed to launch app: {}", e))?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("App launch not implemented for this OS.".to_string())
    }
}

fn main() -> Result<(), eframe::Error> {
    let args: Vec<String> = env::args().collect();
    let mut is_updater_mode = false;
    for argument in &args {
        if argument == "--update" {
	        is_updater_mode = true;
	        break;
	    }
    }

    let mut viewport_builder = egui::ViewportBuilder::default()
        .with_inner_size(egui::vec2(400.0, 160.0))
        .with_min_inner_size(egui::vec2(400.0, 160.0))
        .with_max_inner_size(egui::vec2(400.0, 160.0))
        .with_resizable(false)
        .with_maximize_button(false)
        .with_minimize_button(false)
        .with_title(INSTALLER_NAME);

    if let Ok(image) = image::load_from_memory(APP_ICON_BYTES) {
        let pixels = image.to_rgba8();
        let (width, height) = pixels.dimensions();
        let icon_data = egui::IconData {
            rgba: pixels.into_vec(),
            width,
            height,
        };
        viewport_builder = viewport_builder.with_icon(icon_data);
    } else {
        eprintln!("Failed to load application icon from bytes.");
    }

    let options = eframe::NativeOptions {
        viewport: viewport_builder,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        INSTALLER_NAME,
        options,
        Box::new(|_cc| Ok(Box::new(InstallerApp::new(is_updater_mode)) as Box<dyn eframe::App>)),
    )
}

struct AppState {
    progress: f32,
    installing: bool,
    done: bool,
    success: bool,
    current_action: String,
    download_detail: String,
    app_installed: bool,
    show_close_app_prompt: bool,
    is_updater_mode: bool,
    last_repaint_time: Instant, // Added for repaint rate limiting
    previous_progress: f32, // Added to track progress changes
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            progress: 0.0,
            installing: false,
            done: false,
            success: false,
            current_action: if check_if_app_installed() {
                "Already Installed".to_string()
            } else {
                "Ready.".to_string()
            },
            download_detail: if check_if_app_installed() {
                format!("{} is already installed in your system. Do you want to overwrite the existing installation?", APP_NAME).to_string()
            } else {
                "".to_string()
            },
            app_installed: check_if_app_installed(),
            show_close_app_prompt: false,
            is_updater_mode: false,
            last_repaint_time: Instant::now(), // Initialize
            previous_progress: -1.0, // Initialize
        }
    }
}

struct InstallerApp {
    state: Arc<Mutex<AppState>>,
    app_logo_texture: Option<egui::TextureHandle>,
    initial_install_triggered: bool,
    // Add flags to prevent repeated repaint requests for static states
    was_showing_close_app_prompt: bool,
    was_app_installed_and_not_installing: bool,
    was_done: bool,
}

impl InstallerApp {
    fn new(is_updater_mode: bool) -> Self {
        let initial_state = AppState {
            is_updater_mode,
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(initial_state)),
            app_logo_texture: None,
            initial_install_triggered: false,
            was_showing_close_app_prompt: false,
            was_app_installed_and_not_installing: false,
            was_done: false,
        }
    }
}

impl eframe::App for InstallerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.app_logo_texture.is_none() {
            if let Ok(image) = image::load_from_memory(APP_ICON_BYTES) {
                let size = [image.width() as _, image.height() as _];
                let image_buffer = image.to_rgba8();
                let pixels = egui::ColorImage::from_rgba_unmultiplied(size, image_buffer.into_vec().as_slice());
                self.app_logo_texture = Some(ctx.load_texture("app_logo", pixels, Default::default()));
            } else {
                eprintln!("Failed to load logo for UI display.");
            }
        }

        let current_state_copy = {
            let state_guard = match self.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    eprintln!("Mutex was poisoned: {:?}", poisoned);
                    poisoned.into_inner()
                }
            };
            AppState {
                progress: state_guard.progress,
                installing: state_guard.installing,
                done: state_guard.done,
                success: state_guard.success,
                current_action: state_guard.current_action.clone(),
                download_detail: state_guard.download_detail.clone(),
                app_installed: state_guard.app_installed,
                show_close_app_prompt: state_guard.show_close_app_prompt,
                is_updater_mode: state_guard.is_updater_mode,
                last_repaint_time: state_guard.last_repaint_time, // Copy this too
                previous_progress: state_guard.previous_progress, // Copy this too
            }
        };

        let mut trigger_install_check = false;

        // Initial check for app running ONLY when the installer/updater is first presented
        if !current_state_copy.installing && !current_state_copy.done && !self.initial_install_triggered {
            if current_state_copy.is_updater_mode || (!current_state_copy.app_installed && !current_state_copy.is_updater_mode) {
                if check_process_running(APP_EXECUTABLE_NAME) {
                    let mut state_guard = self.state.lock().unwrap();
                    state_guard.show_close_app_prompt = true;
                    state_guard.installing = false;
                    state_guard.current_action = "Application is Running".to_string();
                    state_guard.download_detail = format!("Please close {} to continue the update.", APP_NAME).to_string();
                    drop(state_guard);
                    ctx.request_repaint(); // Request repaint to show the prompt
                    self.was_showing_close_app_prompt = true; // Mark as shown
                } else {
                    // Only trigger if app is not running initially
                    if current_state_copy.is_updater_mode || !current_state_copy.app_installed {
                        trigger_install_check = true;
                        self.initial_install_triggered = true;
                    }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.add_space(8.0);

                if let Some(logo_texture) = &self.app_logo_texture {
                    ui.add(egui::Image::new(logo_texture).max_size(egui::vec2(40.0, 40.0)));
                }

                ui.add_space(5.0);

                ui.vertical(|ui| {
                    ui.add_space(7.0);
                    let action_text = if current_state_copy.is_updater_mode && !current_state_copy.done {
                        "Updating, please wait...".to_string()
                    } else {
                        current_state_copy.current_action.clone()
                    };
                    ui.heading(&action_text);
                });
            });

            ui.add_space(11.0);

            ui.horizontal(|ui| {
                ui.add_space(8.0);
                let detail_text = if current_state_copy.is_updater_mode && !current_state_copy.done && current_state_copy.download_detail.is_empty() {
                    "Checking for updates...".to_string()
                } else {
                    current_state_copy.download_detail.clone()
                };
                ui.add(egui::Label::new(egui::RichText::new(&detail_text).line_height(Some(20.0))).wrap());
            });

            ui.add_space(8.0);

            if current_state_copy.installing {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.add(egui::ProgressBar::new(current_state_copy.progress).show_percentage());
                    ui.add_space(10.0);
                });
                ui.add_space(10.0);
            }

            ui.vertical_centered(|ui| {
                let button_height = 30.0;
                let button_width = 182.0;

                ui.style_mut().spacing.button_padding = egui::vec2(15.0, 8.0);
                ui.style_mut().visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(10);
                ui.style_mut().visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(10);
                ui.style_mut().visuals.widgets.active.corner_radius = egui::CornerRadius::same(10);

                if current_state_copy.show_close_app_prompt {
                    if !self.was_showing_close_app_prompt {
                        ctx.request_repaint(); // Request repaint only once when prompt appears
                        self.was_showing_close_app_prompt = true;
                    }
                    ui.add_space(5.0);
                    if ui.button("Retry").clicked() {
                        let mut state_guard = self.state.lock().unwrap();
                        state_guard.show_close_app_prompt = false;
                        state_guard.current_action = "Ready.".to_string();
                        state_guard.download_detail = "".to_string();
                        self.initial_install_triggered = false; // Allow re-check
                        drop(state_guard);
                        ctx.request_repaint(); // Request repaint to remove prompt
                        self.was_showing_close_app_prompt = false; // Reset flag
                    }
                } else {
                    // Reset show_close_app_prompt flag if no longer active
                    if self.was_showing_close_app_prompt {
                        self.was_showing_close_app_prompt = false;
                        ctx.request_repaint(); // Repaint if prompt was just dismissed
                    }

                    if current_state_copy.app_installed && !current_state_copy.installing && !current_state_copy.done {
                        if !self.was_app_installed_and_not_installing {
                            ctx.request_repaint(); // Request repaint once entering this state
                            self.was_app_installed_and_not_installing = true;
                        }
                        ui.with_layout(egui::Layout::centered_and_justified(egui::Direction::LeftToRight), |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(5.0);
                                if ui.add(egui::Button::new("Overwrite").min_size(egui::vec2(button_width, button_height))).clicked() {
                                    // Check process running AGAIN when overwrite is clicked
                                    if check_process_running(APP_EXECUTABLE_NAME) {
                                        let mut state_guard = self.state.lock().unwrap();
                                        state_guard.show_close_app_prompt = true;
                                        state_guard.current_action = "Application is Running".to_string();
                                        state_guard.download_detail = format!("Please close {} to continue the overwrite.", APP_NAME).to_string();
                                        drop(state_guard);
                                        ctx.request_repaint();
                                        self.was_showing_close_app_prompt = true; // Mark as shown
                                    } else {
                                        trigger_install_check = true;
                                    }
                                }
                                if ui.add(egui::Button::new("Launch App").min_size(egui::vec2(button_width, button_height))).clicked() {
                                    if let Ok(_) = launch_app() {
                                        let ctx = ctx.clone();
                                        std::thread::spawn(move || {
                                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                        });
                                    } else {
                                        let mut state_guard = self.state.lock().unwrap();
                                        state_guard.current_action = "Failed to launch app.".to_string();
                                        ctx.request_repaint();
                                    }
                                }
                            });
                        });
                    } else {
                        // Reset flag if no longer in this state
                        if self.was_app_installed_and_not_installing {
                            self.was_app_installed_and_not_installing = false;
                            ctx.request_repaint();
                        }

                        if !current_state_copy.installing && !current_state_copy.done && !trigger_install_check {
                            // Only show "Install App" if not already installed and not in updater mode
                            if !current_state_copy.app_installed && !current_state_copy.is_updater_mode {
                                if ui.button("Install App").clicked() {
                                    // Check process running AGAIN when install is clicked
                                    if check_process_running(APP_EXECUTABLE_NAME) {
                                        let mut state_guard = self.state.lock().unwrap();
                                        state_guard.show_close_app_prompt = true;
                                        state_guard.current_action = "Application is Running".to_string();
                                        state_guard.download_detail = format!("Please close {} to continue the installation.", APP_NAME).to_string();
                                        drop(state_guard);
                                        ctx.request_repaint();
                                        self.was_showing_close_app_prompt = true; // Mark as shown
                                    } else {
                                        trigger_install_check = true;
                                    }
                                }
                            }
                        }
                    }
                }

                if current_state_copy.done {
                    if !self.was_done {
                        ctx.request_repaint(); // Request repaint once entering "done" state
                        self.was_done = true;
                    }
                    if current_state_copy.success {
                        ui.add_space(5.0);
                        if ui.button("Launch App").clicked() {
                            if let Ok(_) = launch_app() {
                                let ctx = ctx.clone();
                                std::thread::spawn(move || {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                });
                            } else {
                                let mut state_guard = self.state.lock().unwrap();
                                state_guard.current_action = "Failed to launch app.".to_string();
                                ctx.request_repaint();
                            }
                        }
                    } else {
                        ui.add_space(3.0);
                        if ui.button("Retry Installation").clicked() {
                            let mut state_guard = self.state.lock().unwrap();
                            *state_guard = AppState::default(); // Reset state
                            state_guard.is_updater_mode = current_state_copy.is_updater_mode;
                            self.initial_install_triggered = false; // Allow re-check
                            drop(state_guard);
                            ctx.request_repaint();
                            self.was_done = false; // Reset flag
                        }
                    }
                } else {
                    // Reset was_done flag if no longer done
                    if self.was_done {
                        self.was_done = false;
                        ctx.request_repaint();
                    }
                }
            });
        });

        if trigger_install_check {
            let state_clone_for_thread = Arc::clone(&self.state);
            let ctx_clone = ctx.clone();
            let is_updater_mode_thread = current_state_copy.is_updater_mode;

            thread::spawn(move || {
                // Initial state update (will cause one repaint)
                update_state(&state_clone_for_thread, &ctx_clone, 0.0, true, false, false, "Checking application status...", "");

                install(&state_clone_for_thread, &ctx_clone);

                // Final state update
                let mut state_guard = state_clone_for_thread.lock().unwrap();
                state_guard.app_installed = check_if_app_installed();
                drop(state_guard);
                ctx_clone.request_repaint(); // Ensure final state is drawn

		        let final_state = state_clone_for_thread.lock().unwrap();
                if final_state.success && is_updater_mode_thread {
                    ctx_clone.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        }
    }
}

// Modified update_state function to rate-limit repaints
fn update_state(app_state_arc: &Arc<Mutex<AppState>>, ctx_clone: &egui::Context, progress: f32, installing: bool, done: bool, success: bool, current_action: &str, download_detail: &str) {
    let mut state_guard = app_state_arc.lock().unwrap();

    let now = Instant::now();
    let min_repaint_interval = std::time::Duration::from_millis(100); // 100ms interval for updates

    // Check if enough time has passed OR if the status/action/detail has changed OR if progress has changed significantly
    let should_repaint = (now.duration_since(state_guard.last_repaint_time) > min_repaint_interval) ||
                         (state_guard.current_action != current_action) ||
                         (state_guard.download_detail != download_detail) ||
                         (state_guard.installing != installing) ||
                         (state_guard.done != done) ||
                         (state_guard.success != success) ||
                         ((progress * 100.0).round() != (state_guard.previous_progress * 100.0).round()); // Repaint only if percentage changes

    state_guard.progress = progress;
    state_guard.installing = installing;
    state_guard.done = done;
    state_guard.success = success;
    state_guard.current_action = current_action.to_string();
    state_guard.download_detail = download_detail.to_string();

    if should_repaint {
        state_guard.last_repaint_time = now;
        state_guard.previous_progress = progress; // Update previous progress for next comparison
        drop(state_guard); // Release the lock before requesting repaint
        ctx_clone.request_repaint();
    }
}


fn install(app_state_arc: &Arc<Mutex<AppState>>, ctx_clone: &egui::Context) {
    // The update_state function now handles the repaint logic and rate-limiting
    // We pass app_state_arc and ctx_clone to it directly.

    update_state(app_state_arc, ctx_clone, 0.0, true, false, false, "Installing, please wait...", "Fetching latest version info...");

    let download_url: String;

    let json_response_text = match reqwest::blocking::get(JSON_FEED_URL) {
        Ok(response) => {
            if response.status().is_success() {
                match response.text() {
                    Ok(text) => text,
                    Err(e) => {
                        update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", &format!("Failed to read JSON response: {}", e));
                        return;
                    }
                }
            } else {
                update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", &format!("Failed to fetch version info: HTTP {}", response.status()));
                return;
            }
        },
        Err(e) => {
            update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", &format!("Failed to connect to version info URL: {}", e));
            return;
        }
    };

    let parsed_json = match json::parse(&json_response_text) {
        Ok(parsed) => parsed,
        Err(e) => {
            update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", &format!("Failed to parse version JSON: {}", e));
            return;
        }
    };

    if let (Some(url), Some(_updatedon)) = (parsed_json["url"].as_str(), parsed_json["updatedon"].as_i64()) {
        download_url = url.to_string();
    } else {
        update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", "Invalid JSON format for version information. Expected an object with 'url' and 'updatedon' fields.");
        return;
    }

    update_state(app_state_arc, ctx_clone, 0.0, true, false, false, "Installing, please wait...", "Downloading package");

    let mut resp = match get(&download_url) {
        Ok(r) => r,
        Err(e) => {
            update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", "Couldn't download the package. Please check your internet connection and try again.");
            return;
        }
    };

    let tmp_7z = std::env::temp_dir().join(format!("{}.7z", APP_NAME));
    let mut out = match File::create(&tmp_7z) {
        Ok(f) => f,
        Err(_e) => {
            update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", "Failed to create temporary file");
            return;
        }
    };

    let total_size = resp.content_length();
    let mut downloaded_bytes: u64 = 0;
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = match resp.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_e) => {
                update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", "Couldn't download the package. Please check your internet connection and try again.");
                return;
            }
        };

        if let Err(e) = out.write_all(&buffer[..bytes_read]) {
            update_state(app_state_arc, ctx_clone, 0.0, false, true, false, "Installation Failed", "Couldn't download the package. Please check your internet connection and try again.");
            return;
        }

        downloaded_bytes += bytes_read as u64;

        if let Some(total) = total_size {
            let download_progress = (downloaded_bytes as f32 / total as f32) * 0.5;
            update_state(app_state_arc, ctx_clone, download_progress, true, false, false, "Installing, please wait...", &format!("Downloading package ({:.2} MB / {:.2} MB)", downloaded_bytes as f32 / 1024.0 / 1024.0, total as f32 / 1024.0 / 1024.0));
        } else {
            update_state(app_state_arc, ctx_clone, 0.0 + (downloaded_bytes as f32 * 0.0000001).min(0.49), true, false, false, "Installing, please wait...", &format!("Downloading package ({:.2} MB)", downloaded_bytes as f32 / 1024.0 / 1024.0));
        }
    }

    update_state(app_state_arc, ctx_clone, 0.5, true, false, false, "Installing, please wait...", "Extracting files...");

    let install_dir = get_install_path();

    update_state(app_state_arc, ctx_clone, 0.5, true, false, false, "Installing, please wait...", "Closing application...");
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill")
            .arg("/f")
            .arg("/im")
            .arg(APP_EXECUTABLE_NAME)
            .creation_flags(0x08000000)
            .output();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    update_state(app_state_arc, ctx_clone, 0.5, true, false, false, "Installing, please wait...", "Cleaning old files...");

    if install_dir.exists() {
        let current_exe_path = match env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", &format!("Failed to get current executable path: {}", e));
                return;
            }
        };
        let current_exe_file_name = current_exe_path.file_name()
                                                    .and_then(|s| s.to_str())
                                                    .unwrap_or("");
        
        let uninstaller_cmd_name = format!("{}_uninstall.cmd", APP_NAME.to_lowercase());
        let run_silent_vbs_name = format!("{}_run_silent_uninstall.vbs", APP_NAME.to_lowercase());
        let show_message_vbs_name = format!("{}_uninstall_success_msg.vbs", APP_NAME.to_lowercase());
        let confirm_message_vbs_name = format!("{}_uninstall_confirm_msg.vbs", APP_NAME.to_lowercase());
        let cleanup_cmd_name = format!("{}_uninstall_cleanup.cmd", APP_NAME.to_lowercase());


        if let Ok(entries) = fs::read_dir(&install_dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let entry_path = entry.path();
                    if let Some(file_name) = entry_path.file_name().and_then(|s| s.to_str()) {
                        if file_name != current_exe_file_name && 
                           file_name != uninstaller_cmd_name &&
                           file_name != run_silent_vbs_name &&
                           file_name != show_message_vbs_name &&
                           file_name != confirm_message_vbs_name &&
                           file_name != cleanup_cmd_name {
                            if entry_path.is_file() {
                                if let Err(e) = fs::remove_file(&entry_path) {
                                    update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", &format!("Failed to remove old file '{}': {}", entry_path.display(), e));
                                    return;
                                }
                            } else if entry_path.is_dir() {
                                if let Err(e) = fs::remove_dir_all(&entry_path) {
                                    update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", &format!("Failed to remove old directory '{}': {}", entry_path.display(), e));
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", "Failed to read existing installation directory for cleanup.");
            return;
        }
    }
    
    if let Err(e) = fs::create_dir_all(&install_dir) {
        update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", "Failed to create installation directory");
        return;
    }

    let file_bytes = match fs::read(&tmp_7z) {
        Ok(bytes) => bytes,
        Err(e) => {
            update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", "Failed to read downloaded .7z file");
            return;
        }
    };

    let file_size = file_bytes.len() as u64;
    let password = sevenz_rust::Password::empty();

    let mut reader = match sevenz_rust::SevenZReader::new(std::io::Cursor::new(file_bytes), file_size, password) {
        Ok(r) => r,
        Err(e) => {
            update_state(app_state_arc, ctx_clone, 0.5, false, true, false, "Installation Failed", "Failed to open 7z archive");
            return;
        }
    };

    let _ = reader.for_each_entries(|entry, reader| {
        let out_path = install_dir.join(&entry.name);

        if entry.is_directory {
            if let Err(_) = fs::create_dir_all(&out_path) {
                return Err(sevenz_rust::Error::Other("Failed to create directory from 7z".into()));
            }
        } else {
            if let Some(parent) = out_path.parent() {
                if let Err(_) = fs::create_dir_all(parent) {
                    return Err(sevenz_rust::Error::Other("Failed to create parent directory for extracted file from 7z".into()));
                }
            }
            let mut outfile = match File::create(&out_path) {
                Ok(f) => f,
                Err(_) => {
                    return Err(sevenz_rust::Error::Other("Failed to create extracted file from 7z".into()));
                }
            };

            if let Err(_) = std::io::copy(reader, &mut outfile) {
                return Err(sevenz_rust::Error::Other("Failed to copy data during 7z extraction".into()));
            }
        }
        Ok(true)
    });

    update_state(app_state_arc, ctx_clone, 0.9, true, false, false, "Installing, please wait...", "Organizing files...");

    if !SUBFOLDER_NAME.is_empty() {
        let extracted_subfolder_path = install_dir.join(SUBFOLDER_NAME);

        if extracted_subfolder_path.exists() && extracted_subfolder_path.is_dir() {
            update_state(app_state_arc, ctx_clone, 0.9, true, false, false, "Installing, please wait...", "Organizing files...");

            if let Ok(entries) = fs::read_dir(&extracted_subfolder_path) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let source_path = entry.path();
                        let destination_path = install_dir.join(entry.file_name().to_str().unwrap());

                        if let Some(parent) = destination_path.parent() {
                            if !parent.exists() {
                                if let Err(e) = fs::create_dir_all(parent) {
                                    update_state(app_state_arc, ctx_clone, 0.9,  false, true, false, "Installation Failed", &format!("Error: {}", e));
                                    return;
                                }
                            }
                        }

                        if let Err(e) = fs::rename(&source_path, &destination_path) {
                            update_state(app_state_arc, ctx_clone, 0.9, false, true, false, "Installation Failed", &format!("Error: {}", e));
                            let _ = fs::remove_dir_all(&extracted_subfolder_path);
                            return;
                        }
                    }
                }
            } else {
                update_state(app_state_arc, ctx_clone, 0.9, false, true, false, "Installation Failed", "Could not read content to organize.");
                return;
            }

            if let Err(e) = fs::remove_dir_all(&extracted_subfolder_path) {
                eprintln!("Warning: Failed to remove empty extracted subfolder '{}': {}", extracted_subfolder_path.display(), e);
            }
        }
    }

    let current_is_updater_mode = app_state_arc.lock().unwrap().is_updater_mode;
    if !current_is_updater_mode {
        update_state(app_state_arc, ctx_clone, 0.9, true, false, false, "Installation Completed", "Copying installer...");
        if let Err(e) = copy_self_to_install_path(&install_dir) {
            eprintln!("Warning: Failed to copy installer to install path: {}", e);
        }
    }

    update_state(app_state_arc, ctx_clone, 0.93, true, false, false, "Installation Completed", "Creating uninstaller...");

    if let Err(e) = create_uninstaller(&install_dir) {
        eprintln!("Warning: Failed to create uninstaller: {}", e);
    }

    update_state(app_state_arc, ctx_clone, 0.95, true, false, false, "Installation Completed", "Creating shortcut...");
    if let Err(e) = create_shortcut(&install_dir) {
        update_state(app_state_arc, ctx_clone, 0.95, false, true, false, "Installation Failed", "Failed to create shortcut");
        return;
    }

    if let Err(e) = register_in_windows_registry(&install_dir) {
        eprintln!("Warning: Failed to register in Windows registry: {}", e);
    }

    let _ = fs::remove_file(&tmp_7z);

    update_state(app_state_arc, ctx_clone, 1.0, false, true, true, "Installation Completed", "Ready to launch!");
}