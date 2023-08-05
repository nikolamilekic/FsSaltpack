module SaltShaker.MainView

open Avalonia.FuncUI.DSL
open Avalonia.Layout
open Avalonia.Controls

let make state dispatch = TabControl.create [
    Layoutable.margin 0.
    TabControl.viewItems [
        TabItem.create [
            TabItem.header "Key Settings"
            TabItem.content (KeyView.make state.KeyViewState (KeyViewCommand >> dispatch))
        ]
        TabItem.create [
            TabItem.header "Encrypt"
            TabItem.content (EncryptView.make state.EncryptViewState (EncryptViewCommand >> dispatch))
            TabItem.isVisible state.EncryptionEnabled
        ]
        TabItem.create [
            TabItem.header "Decrypt"
            TabItem.content (DecryptView.make state.DecryptViewState (DecryptViewCommand >> dispatch))
            TabItem.isVisible state.DecryptionEnabled
        ]
    ]
]
