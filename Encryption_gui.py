import PySimpleGUI as Psg
import Encryption

Psg.theme('SandyBeach')
POPUP = 'Psg.popup("Not Implemented")'
SYM_MENU_BUTTONS = ["Authenticated Encryption", "Unauthenticated Encryption",
                    "Authenticated Decryption", "Unauthenticated Decryption"]
SYM_ALGOS = ['test1', 'test2', 'test3']


def MainMenuWindow():
    layout = [[Psg.Text("Select which method of Encryption / Decryption\nyou want to perform",
                        font="Lucida",
                        justification='left')],
              [Psg.Button("Asymmetric Encryption"), Psg.Button("Symmetric Encryption"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Main Menu",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymMenuWindow():
    layout = [[Psg.Text("Asymmetric Encryption / Decryption",
                        font="Lucida")],
              [Psg.Button("Encryption"), Psg.Button("Decryption")],
              [Psg.Button("Generate Keys", key="key"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Asymmetric Encryption / Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymEncWindow():
    layout = [[Psg.Text("Asymmetric Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(key="PubKey"), Psg.FileBrowse("Public Key")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]
    
    return Psg.Window(title="Asymmetric Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymDecWindow():
    layout = [[Psg.Text("Asymmetric Decryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload Encrypted File")],
              [Psg.Input(key="PrivKey"), Psg.FileBrowse("Private Key")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Asymmetric Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymGenPrivKeyWindow():
    layout = [[Psg.Text("Generate Private Key",
                        font="Lucida")],
              [Psg.Input(), Psg.FolderBrowse("PrivateKeyFolder",
                                             key="PrivKeyFolder")],
              [Psg.Input("priv_key.pem",
                         key="PrivKeyName")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Generate Private key",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)
    

def AsymGenPubKeyWindow():
    layout = [[Psg.Text("Generate Public Key",
                        font="Lucida")],
              [Psg.Input(""), Psg.FileBrowse("Upload Private Key",
                                             key="PrivKey")],
              [Psg.Input(""), Psg.FolderBrowse("PrivateKeyFolder",
                                               key="PubKeyFolder")],
              [Psg.Input("pub_key.pub",
                         size=(20, 1),
                         key="PubKeyName")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Generate Public key",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymGenKeysWindow():
    layout = [[Psg.Text("Generate Keys",
                        font="Lucida")],
              [Psg.Button("Generate Private Key", key="GenPrivKey"),
               Psg.Button("Generate Public Key", key="GenPubKey")],
              [Psg.Button("Exit", key="Exit")]]

    return Psg.Window(title="Generate Keys",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymMenuWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption",
                        font="Lucida")],
              [Psg.Combo(SYM_ALGOS,
                         key="SymAlgo"),
               Psg.Button("Update",
                          key="SymAlgoUpdate")],
              [Psg.Button(SYM_MENU_BUTTONS[0]), Psg.Button(SYM_MENU_BUTTONS[1])],
              [Psg.Button(SYM_MENU_BUTTONS[2]), Psg.Button(SYM_MENU_BUTTONS[3])],
              [Psg.Button("Settings"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*", key="Password"), Psg.Text("Password")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*"), Psg.Text("Password")],
              [Psg.Input(key="Key"), Psg.FileBrowse("Key File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymUnAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymUnAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymEncSettingWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption Config",
                        font="Lucida")],
              [Psg.Text("key"), Psg.Text(Encryption.DisplayConfigFile()[0])],
              [Psg.Text("iv"), Psg.Text(Encryption.DisplayConfigFile()[1])],
              [Psg.Button("Regenerate"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption Config",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymEncWindowFunc():
    asym_enc_window = AsymEncWindow()
    
    while True:
        event, values = asym_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break

        if event == "Submit":
            enc_file = Encryption.AsymmetricEncDecFile(filename=values.get("Filename"),
                                                       output_folder=values.get("OutFolder"))
            enc_file.AsymmetricEncFile(pub_key=values.get("PubKey"))
            Psg.Popup("Successful",
                      location=(800, 600))
    
    asym_enc_window.close()


def AsymDecWindowFunc():
    asym_dec_window = AsymDecWindow()
    
    while True:
        event, values = asym_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "Submit":
            dec_file = Encryption.AsymmetricEncDecFile(filename=values.get("Filename"),
                                                       output_folder=values.get("OutFolder"))
            dec_file.AsymmetricDecFile(priva_key=values.get("PrivKey"))
            Psg.Popup("Successful",
                      location=(800, 600))
            
    asym_dec_window.close()


def AsymGenPrivKeyWindowFunc():
    asym_gen_priv_key_window = AsymGenPrivKeyWindow()

    while True:
        event, values = asym_gen_priv_key_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
    
        if event == "Submit":
            print("AsymGenPrivKeyWindowFunc:\n", values)

    asym_gen_priv_key_window.close()


def AsymGenPubKeyWindowFunc():
    asym_gen_pub_key_window = AsymGenPubKeyWindow()
    
    while True:
        event, values = asym_gen_pub_key_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if event == "Submit":
            print("AsymGenPrivKeyWindowFunc:\n", values)
            
    asym_gen_pub_key_window.close()


def AsymGenKeysWindowFunc():
    asym_gen_keys_window = AsymGenKeysWindow()
    
    while True:
        event, values = asym_gen_keys_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "GenPrivKey":
            AsymGenPrivKeyWindowFunc()
        
        elif event == "GenPubKey":
            AsymGenPubKeyWindowFunc()
    
    asym_gen_keys_window.close()


def AsymMenuWindowFunc():
    asym_menu_window = AsymMenuWindow()
    
    while True:
        event, values = asym_menu_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "Encryption":
            AsymEncWindowFunc()
        
        elif event == "Decryption":
            AsymDecWindowFunc()
        
        elif event == "key":
            AsymGenKeysWindowFunc()
    
    asym_menu_window.close()


def SymAuthEncWindowFunc():
    sym_auth_enc_window = SymAuthEncWindow()
    
    while True:
        event, values = sym_auth_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "Submit":
            enc_file = Encryption.SymmetricEncDecFileWithAuth(filename=values.get("Filename"),
                                                              auth_tag=values.get('Password'),
                                                              output=values.get('OutFolder'))
            enc_file.SymmetricEncFile()
    
    sym_auth_enc_window.close()


def SymUnauthEncWindowFunc():
    sym_unauth_enc_window = SymUnAuthEncWindow()
    
    while True:
        event, values = sym_unauth_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if event == "Submit":
            enc_file = Encryption.SymmetricEncDecFileWithoutAuth(filename=values.get("Filename"),
                                                                 output=values.get("OutFolder"))
            enc_file.SymmetricEncWithoutAuth()
    
    sym_unauth_enc_window.close()


def SymAuthDecWindowFunc():
    sym_auth_dec_window = SymAuthDecWindow()
    
    while True:
        event, values = sym_auth_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if event == "Submit":
            dec_file = Encryption.SymmetricEncDecFileWithAuth(filename=values.get("Filename"),
                                                              auth_tag=values.get('Password'),
                                                              output=values.get('OutFolder'))
            
            dec_file.SymmetricDecFile(key=values.get("Key"))
    
    sym_auth_dec_window.close()


def SymUnAuthDecWindowFunc():
    sym_unauth_dec_window = SymUnAuthDecWindow()
    
    while True:
        event, values = sym_unauth_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if event == "Submit":
            dec_file = Encryption.SymmetricEncDecFileWithoutAuth(filename=values.get("Filename"),
                                                                 output=values.get("OutFolder"))
            dec_file.SymmetricDecWithoutAuth()
    
    sym_unauth_dec_window.close()


def SymSettingWindowFunc():
    sym_enc_setting_window = SymEncSettingWindow()
    
    while True:
        event, values = sym_enc_setting_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break

        if event == "Regenerate":
            Encryption.GenerateConfigFile()
    
    sym_enc_setting_window.close()


def SymMenuWindowFunc():
    sym_menu_window = SymMenuWindow()
    
    while True:
        event, values = sym_menu_window.read()
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == SYM_MENU_BUTTONS[0]:
            SymAuthEncWindowFunc()
        
        elif event == SYM_MENU_BUTTONS[1]:
            SymUnauthEncWindowFunc()
        
        elif event == SYM_MENU_BUTTONS[2]:
            SymAuthDecWindowFunc()
        
        elif event == SYM_MENU_BUTTONS[3]:
            SymUnAuthDecWindowFunc()
        
        elif event == "Settings":
            SymSettingWindowFunc()
        
        elif event == "SymAlgoUpdate":
            print(values['SymAlgo'])
    
    sym_menu_window.close()


def main():
    main_menu_window = MainMenuWindow()
    while True:
        event, values = main_menu_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "Asymmetric Encryption":
            AsymMenuWindowFunc()
                    
        elif event == "Symmetric Encryption":
            SymMenuWindowFunc()
    main_menu_window.close()


if __name__ == "__main__":
    main()
