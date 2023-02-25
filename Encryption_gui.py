import PySimpleGUI as Psg
import Encryption
import os

Psg.theme('SandyBeach')
SYM_MENU_BUTTONS = ["Authenticated Encryption", "Unauthenticated Encryption",
                    "Authenticated Decryption", "Unauthenticated Decryption"]
SYM_UNAUTH_ALGOS = ["AES ECB", "AES CBC", "AES OFB", "AES CTR", "Blowfish ECB", "Blowfish CBC", "ChaCha20", "3DES CBC",
                    "Camellia ECB", "Camellia CBC"]
SYM_AUTH_ALGOS = ["AES GCM"]


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
              [Psg.Button("Generate Keys", key="key"), Psg.Button("Back")]]
    
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
              [Psg.Submit(), Psg.Button("Back")]]
    
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
              [Psg.Submit(), Psg.Button("Back")]]

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
              [Psg.Submit(), Psg.Button("Back")]]

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
              [Psg.Submit(), Psg.Button("Back")]]

    return Psg.Window(title="Generate Public key",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymGenKeysWindow():
    layout = [[Psg.Text("Generate Keys",
                        font="Lucida")],
              [Psg.Button("Generate Private Key", key="GenPrivKey"),
               Psg.Button("Generate Public Key", key="GenPubKey")],
              [Psg.Button("Back", key="Back")]]

    return Psg.Window(title="Generate Keys",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymMenuWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption",
                        font="Lucida")],
              [Psg.Button(SYM_MENU_BUTTONS[0]), Psg.Button(SYM_MENU_BUTTONS[1])],
              [Psg.Button(SYM_MENU_BUTTONS[2]), Psg.Button(SYM_MENU_BUTTONS[3])],
              [Psg.Button("Settings"), Psg.Button("Back")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymAuthWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption / Decryption",
                        font="Lucida")],
              [Psg.Combo(SYM_AUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_AUTH_ALGOS[0])],
              [Psg.Button(SYM_MENU_BUTTONS[0]), Psg.Button(SYM_MENU_BUTTONS[2])],
              [Psg.Button("Back")]]

    return Psg.Window(title="Symmetric Authenticated Encryption / Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymUnAuthWindow():
    layout = [[Psg.Text("Symmetric Unauthenticated Encryption / Decryption",
                        font="Lucida")],
              [Psg.Combo(SYM_UNAUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_UNAUTH_ALGOS[0])],
              [Psg.Button(SYM_MENU_BUTTONS[1]), Psg.Button(SYM_MENU_BUTTONS[3])],
              [Psg.Button("Back")]]

    return Psg.Window(title="Symmetric Unauthenticated Encryption / Decryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)
    

def SymAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*", key="Password"), Psg.Text("Password")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Combo(SYM_AUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_AUTH_ALGOS[0]), Psg.Submit(), Psg.Button("Back")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Decryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*", key="Password"), Psg.Text("Password")],
              [Psg.Input(key="Key"), Psg.FileBrowse("Key File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Combo(SYM_AUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_AUTH_ALGOS[0]), Psg.Submit(), Psg.Button("Back")]]
    
    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymUnAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Combo(SYM_UNAUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_UNAUTH_ALGOS[0]), Psg.Submit(), Psg.Button("Back")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymUnAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption",
                        font="Lucida")],
              [Psg.Input(key="Filename"), Psg.FileBrowse("Upload File")],
              [Psg.Input(key="OutFolder"), Psg.FolderBrowse("Output Folder")],
              [Psg.Combo(SYM_UNAUTH_ALGOS,
                         key="SymAlgo",
                         default_value=SYM_UNAUTH_ALGOS[0]), Psg.Submit(), Psg.Button("Back")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def SymEncSettingWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption Config",
                        font="Lucida")],
              [Psg.Text("key"), Psg.Text(Encryption.DisplayConfigFile()[0])],
              [Psg.Text("iv"), Psg.Text(Encryption.DisplayConfigFile()[1])],
              [Psg.Button("Regenerate"), Psg.Button("Back")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption Config",
                      layout=layout,
                      location=(800, 600),
                      finalize=True)


def AsymEncWindowFunc():
    asym_enc_window = AsymEncWindow()
    
    while True:
        event, values = asym_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break

        if event == "Submit":
            enc_file = Encryption.AsymmetricEncDecFile(filename=values.get("Filename"),
                                                       output_folder=values.get("OutFolder"))
            enc_file.AsymmetricEncFile(pub_key=values.get("PubKey"))
            Psg.Popup("Successful Encryption")

    asym_enc_window.close()
    AsymMenuWindowFunc()


def AsymDecWindowFunc():
    asym_dec_window = AsymDecWindow()
    
    while True:
        event, values = asym_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Submit":
            dec_file = Encryption.AsymmetricEncDecFile(filename=values.get("Filename"),
                                                       output_folder=values.get("OutFolder"))
            dec_file.AsymmetricDecFile(priva_key=values.get("PrivKey"))
            Psg.Popup("Successful Decryption")

    asym_dec_window.close()
    AsymMenuWindowFunc()


def AsymGenPrivKeyWindowFunc():
    asym_gen_priv_key_window = AsymGenPrivKeyWindow()

    while True:
        event, values = asym_gen_priv_key_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
    
        if event == "Submit":
            priv_key = Encryption.AsymmetricEncryptionPrivateKey(os.path.join(values.get('PrivKeyFolder'),
                                                                              values.get('PrivKeyName')))
            priv_key.GenRSAPrivKey()
            Psg.Popup("Successfully created Private Key.")

    asym_gen_priv_key_window.close()
    AsymGenKeysWindowFunc()


def AsymGenPubKeyWindowFunc():
    asym_gen_pub_key_window = AsymGenPubKeyWindow()
    
    while True:
        event, values = asym_gen_pub_key_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Submit":
            pub_key = Encryption.AsymmetricEncryptionPublicKey(os.path.join(values.get('PubKeyFolder'),
                                                                            values.get('PubKeyName')))
            pub_key.GenPublicKey(values.get('PrivKey'))
            Psg.Popup("Successfully created Public Key.")

    asym_gen_pub_key_window.close()
    AsymGenKeysWindowFunc()


def AsymGenKeysWindowFunc():
    asym_gen_keys_window = AsymGenKeysWindow()
    
    while True:
        event, values = asym_gen_keys_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        if event == "GenPrivKey":
            asym_gen_keys_window.close()
            AsymGenPrivKeyWindowFunc()
        
        elif event == "GenPubKey":
            asym_gen_keys_window.close()
            AsymGenPubKeyWindowFunc()
    
    asym_gen_keys_window.close()
    AsymMenuWindowFunc()


def AsymMenuWindowFunc():
    asym_menu_window = AsymMenuWindow()
    
    while True:
        event, values = asym_menu_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Encryption":
            asym_menu_window.close()
            AsymEncWindowFunc()
            
        elif event == "Decryption":
            asym_menu_window.close()
            AsymDecWindowFunc()
        
        elif event == "key":
            asym_menu_window.close()
            AsymGenKeysWindowFunc()

    asym_menu_window.close()
    main()


def SymAuthEncWindowFunc():
    sym_auth_enc_window = SymAuthEncWindow()
    
    while True:
        event, values = sym_auth_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        if event == "Submit":
            enc_file = Encryption.SymmetricEncDecFileWithAuth(filename=values.get("Filename"),
                                                              auth_tag=values.get('Password'),
                                                              enc_algo=values.get("SymAlgo"),
                                                              output=values.get('OutFolder'))
            enc_file.SymmetricEncFile()
            Psg.Popup("Successful Encryption")
    
    sym_auth_enc_window.close()
    SymMenuWindowFunc()


def SymUnauthEncWindowFunc():
    sym_unauth_enc_window = SymUnAuthEncWindow()
    
    while True:
        event, values = sym_unauth_enc_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Submit":
            enc_file = Encryption.SymmetricEncDecFileWithoutAuth(filename=values.get("Filename"),
                                                                 enc_algo=values.get("SymAlgo"),
                                                                 output=values.get("OutFolder"))
            enc_file.SymmetricEncWithoutAuth()
            Psg.Popup("Successful Encryption")

    sym_unauth_enc_window.close()
    SymMenuWindowFunc()


def SymAuthDecWindowFunc():
    sym_auth_dec_window = SymAuthDecWindow()
    
    while True:
        event, values = sym_auth_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Submit":
            dec_file = Encryption.SymmetricEncDecFileWithAuth(filename=values.get("Filename"),
                                                              auth_tag=values.get('Password'),
                                                              enc_algo=values.get("SymAlgo"),
                                                              output=values.get('OutFolder'))

            dec_file.SymmetricDecFile(key=values.get("Key"))
            Psg.Popup("Successful Decryption")
    
    sym_auth_dec_window.close()
    SymMenuWindowFunc()


def SymUnAuthDecWindowFunc():
    sym_unauth_dec_window = SymUnAuthDecWindow()
    
    while True:
        event, values = sym_unauth_dec_window.read()
        
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        
        if event == "Submit":
            dec_file = Encryption.SymmetricEncDecFileWithoutAuth(filename=values.get("Filename"),
                                                                 enc_algo=values.get("SymAlgo"),
                                                                 output=values.get("OutFolder"))
            dec_file.SymmetricDecWithoutAuth()
            Psg.Popup("Successful Decryption")
    
    sym_unauth_dec_window.close()
    SymMenuWindowFunc()


def SymSettingWindowFunc():
    sym_enc_setting_window = SymEncSettingWindow()
    
    while True:
        event, values = sym_enc_setting_window.read()
        
        if event in (Psg.WIN_CLOSED, "Back"):
            break

        if event == "Regenerate":
            Encryption.GenerateConfigFile()
            sym_enc_setting_window.close()
            SymSettingWindowFunc()
    
    sym_enc_setting_window.close()
    SymMenuWindowFunc()


def SymMenuWindowFunc():
    sym_menu_window = SymMenuWindow()
    
    while True:
        event, values = sym_menu_window.read()
        if event in (Psg.WIN_CLOSED, "Back"):
            break
        if event == SYM_MENU_BUTTONS[0]:
            sym_menu_window.close()
            SymAuthEncWindowFunc()
        
        elif event == SYM_MENU_BUTTONS[1]:
            sym_menu_window.close()
            SymUnauthEncWindowFunc()

        elif event == SYM_MENU_BUTTONS[2]:
            sym_menu_window.close()
            SymAuthDecWindowFunc()

        elif event == SYM_MENU_BUTTONS[3]:
            sym_menu_window.close()
            SymUnAuthDecWindowFunc()
        
        elif event == "Settings":
            sym_menu_window.close()
            SymSettingWindowFunc()
        
    sym_menu_window.close()
    main()


def main():
    main_menu_window = MainMenuWindow()
    while True:
        event, values = main_menu_window.read()
        
        if event in (Psg.WIN_CLOSED, "Exit"):
            break
        if event == "Asymmetric Encryption":
            main_menu_window.close()
            AsymMenuWindowFunc()
                    
        elif event == "Symmetric Encryption":
            main_menu_window.close()
            SymMenuWindowFunc()

    main_menu_window.close()


if __name__ == "__main__":
    main()
