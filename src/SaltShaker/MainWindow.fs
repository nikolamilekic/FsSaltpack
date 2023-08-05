namespace SaltShaker

open System
open System.Reflection
open Avalonia.Media
open Elmish
open Avalonia
open Avalonia.Controls
open Avalonia.FuncUI
open Avalonia.FuncUI.Elmish
open Avalonia.FuncUI.Hosts
open FSharpPlus

type MainWindow() as this =
    inherit HostWindow()

    let view = MainView.make

    let update command state =
        let events = MainViewCommandProcessor.processCommand state command
        let newState = events |> List.fold MainViewEventProcessor.processEvent state
        newState, Cmd.none

    let init _ = zero, []

    let version =
        if String.IsNullOrEmpty ThisAssembly.Git.SemVer.DashLabel
        then $"{ThisAssembly.Git.SemVer.Major}.{ThisAssembly.Git.SemVer.Minor}.{ThisAssembly.Git.SemVer.Patch}"
        else $"{ThisAssembly.Git.BaseVersion.Major}.{ThisAssembly.Git.BaseVersion.Minor}.{ThisAssembly.Git.BaseVersion.Patch}{ThisAssembly.Git.SemVer.DashLabel}.{ThisAssembly.Git.Commits}"

    do
        base.Background <- SolidColorBrush(0xff282828u)
        base.Title <- $"SaltShaker v{version}"
        base.Margin <- Thickness(0.)
        base.Width <- 800.0
        base.Height <- 600.0
        base.MinWidth <- 800.0
        base.MinHeight <- 600.0
        base.Icon <- WindowIcon(
            Assembly
                .GetExecutingAssembly()
                .GetManifestResourceStream("SaltShaker.Lock.ico"))

        #if DEBUG
        this.AttachDevTools()
        #endif

        Elmish.Program.mkProgram init update view
        |> Program.withHost this
        |> Program.run
