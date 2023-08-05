module SaltShaker.EncryptDecryptCommon

open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.FuncUI.Types
open Avalonia.Media

let bigTextBoxProperties : IAttr<TextBox> list = [
    TextBox.multiline true
    TextBox.acceptsReturn true
    TextBox.textWrapping TextWrapping.Wrap
]
