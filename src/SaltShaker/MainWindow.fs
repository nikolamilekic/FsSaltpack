namespace KeyKeeper

open System
open System.Reactive.Disposables
open System.Threading.Tasks
open System.Reflection
open Avalonia.Layout
open Elmish
open Avalonia
open Avalonia.Controls
open Avalonia.Input
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Hosts
open Avalonia.FuncUI.Elmish
open FSharpPlus
open FSharpPlus.Data

type MainWindow() as this =
    inherit HostWindow()

    let view state dispatch = Grid.create []

    let update message state = state, Cmd.none

    let init = (), []

    let version =
        if String.IsNullOrEmpty ThisAssembly.Git.SemVer.DashLabel
        then $"{ThisAssembly.Git.SemVer.Major}.{ThisAssembly.Git.SemVer.Minor}.{ThisAssembly.Git.SemVer.Patch}"
        else $"{ThisAssembly.Git.BaseVersion.Major}.{ThisAssembly.Git.BaseVersion.Minor}.{ThisAssembly.Git.BaseVersion.Patch}{ThisAssembly.Git.SemVer.DashLabel}.{ThisAssembly.Git.Commits}"

    do
        base.Title <- $"SaltShaker v{version}"
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

        Elmish.Program.mkProgram (fun () -> init) update view
        |> Program.withHost this
        |> Program.run
