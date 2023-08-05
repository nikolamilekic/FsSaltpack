namespace SaltShaker

open Avalonia.FuncUI.DSL
open Avalonia.Layout
open Avalonia.Controls

type MainView() =
    let encryptView = EncryptView()
    let decryptView = DecryptView()

    member _.Make state dispatch = TabControl.create [
        Layoutable.margin 0.
        TabControl.viewItems [
            TabItem.create [
                TabItem.header "Key Settings"
                TabItem.content (KeyView.make state.KeyViewState (KeyViewCommand >> dispatch))
            ]
            TabItem.create [
                TabItem.header "Encrypt"
                TabItem.content (encryptView.Make state.EncryptViewState (EncryptViewCommand >> dispatch))
                TabItem.isVisible state.EncryptionEnabled
            ]
            TabItem.create [
                TabItem.header "Decrypt"
                TabItem.content (decryptView.Make state.DecryptViewState (DecryptViewCommand >> dispatch))
                TabItem.isVisible state.DecryptionEnabled
            ]
        ]
    ]
