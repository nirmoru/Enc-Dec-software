import PySimpleGUI as Psg
import Encryption

Psg.theme('SandyBeach')
POPUP = 'Psg.popup("Not Implemented")'
SYM_MENU_BUTTONS = ["Authenticated Encryption", "Unauthenticated Encryption",
                    "Authenticated Decryption", "Unauthenticated Decryption"]
SYM_ALGOS = ['test1', 'test2', 'test3']


def MainMenuWindow():
    layout = [[Psg.Text("Select which method of Encryption / Decryption\nyou want to perform",
                        font='Lucida',
                        justification='left')],
              [Psg.Button("Asymmetric Encryption"), Psg.Button("Symmetric Encryption"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Main Menu", layout=layout, location=(800, 600), finalize=True)


def AsymMenuWindow():
    layout = [[Psg.Text("Asymmetric Encryption / Decryption",
                        font='Lucida')],
              [Psg.Button("Encryption"), Psg.Button("Decryption"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Asymmetric Encryption / Decryption",
                      layout=layout,
                      finalize=True)


def AsymEncWindow():
    layout = [[Psg.Text("Asymmetric Encryption",
                        font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Input(), Psg.FileBrowse("Public Key")],
              [Psg.Input(), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]
    
    return Psg.Window(title="Asymmetric Encryption",
                      layout=layout,
                      finalize=True)


def AsymDecWindow():
    layout = [[Psg.Text("Asymmetric Decryption",
                        font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload Encrypted File")],
              [Psg.Input(), Psg.FileBrowse("Private Key")],
              [Psg.Input(), Psg.FolderBrowse("Output Folder")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Asymmetric Decryption",
                      layout=layout,
                      finalize=True)


def SymMenuWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption")],
              [Psg.Combo(SYM_ALGOS, key="SymAlgo"), Psg.Button("Update", key="SymAlgoUpdate")],
              [Psg.Button(SYM_MENU_BUTTONS[0]), Psg.Button(SYM_MENU_BUTTONS[1])],
              [Psg.Button(SYM_MENU_BUTTONS[2]), Psg.Button(SYM_MENU_BUTTONS[3])],
              [Psg.Button("Settings"), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption",
                      layout=layout,
                      finalize=True)


def SymAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption", size=(20, 1), font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*"), Psg.Text("Password")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      finalize=True)


def SymAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption", size=(20, 1), font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Input(password_char="*"), Psg.Text("Password")],
              [Psg.Submit(), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      finalize=True)


def SymUnAuthEncWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption", size=(20, 1), font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      finalize=True)


def SymUnAuthDecWindow():
    layout = [[Psg.Text("Symmetric Authenticated Encryption", size=(20, 1), font='Lucida')],
              [Psg.Input(), Psg.FileBrowse("Upload File")],
              [Psg.Submit(), Psg.Button("Exit")]]

    return Psg.Window(title="Symmetric Authenticated Encryption",
                      layout=layout,
                      finalize=True)


def SymEncSettingWindow():
    layout = [[Psg.Text("Symmetric Encryption / Decryption Config", size=(20, 1), font='Lucida')],
              [Psg.Text("key"), Psg.Input(Encryption.DisplayConfigFile()[0])],
              [Psg.Text("iv"), Psg.Input(Encryption.DisplayConfigFile()[1])],
              [Psg.Submit(), Psg.Button("Exit")]]
    
    return Psg.Window(title="Symmetric Encryption / Decryption Config",
                      layout=layout,
                      finalize=True)


def AsymEncWindowFunc():
    asym_enc_window = AsymEncWindow()
    
    while True:
        event4, values4 = asym_enc_window.read()
        if event4 in (Psg.WIN_CLOSED, "Exit"):
            break
        if event4 == "Submit":
            eval(POPUP)
    
    asym_enc_window.close()


def AsymDecWindowFunc():
    asym_dec_window = AsymDecWindow()
    
    while True:
        asym_dec_event, asym_dec_values = asym_dec_window.read()
        
        if asym_dec_event in (Psg.WIN_CLOSED, "Exit"):
            break
        if asym_dec_event == "Submit":
            eval(POPUP)
    
    asym_dec_window.close()


def AsymMenuWindowFunc():
    asym_menu_window = AsymMenuWindow()
    
    while True:
        event1, values1 = asym_menu_window.read()
        if event1 in (Psg.WIN_CLOSED, "Exit"):
            break
        if event1 == "Encryption":
            AsymEncWindowFunc()
        
        if event1 == "Decryption":
            AsymDecWindowFunc()
    
    asym_menu_window.close()


def SymAuthEncWindowFunc():
    sym_auth_enc_window = SymAuthEncWindow()
    
    while True:
        sym_auth_enc_event, sym_auth_enc_values = sym_auth_enc_window.read()
        if sym_auth_enc_event in (Psg.WIN_CLOSED, "Exit"):
            break
        if sym_auth_enc_event == "Submit":
            eval(POPUP)
    
    sym_auth_enc_window.close()


def SymUnauthEncWindowFunc():
    sym_unauth_enc_window = SymUnAuthEncWindow()
    
    while True:
        sym_unauth_enc_event, sym_unauth_enc_values = sym_unauth_enc_window.read()
        if sym_unauth_enc_event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if sym_unauth_enc_event == "Submit":
            eval(POPUP)
    
    sym_unauth_enc_window.close()


def SymAuthDecWindowFunc():
    sym_auth_dec_window = SymAuthDecWindow()
    
    while True:
        sym_auth_dec_event, sym_auth_dec_values = sym_auth_dec_window.read()
        
        if sym_auth_dec_event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if sym_auth_dec_event == "Submit":
            eval(POPUP)
    
    sym_auth_dec_window.close()


def SymUnAuthDecWindowFunc():
    sym_unauth_dec_window = SymUnAuthDecWindow()
    
    while True:
        sym_unauth_dec_event, sym_unauth_dec_values = sym_unauth_dec_window.read()
        
        if sym_unauth_dec_event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if sym_unauth_dec_event == "Submit":
            eval(POPUP)
    
    sym_unauth_dec_window.close()


def SymSettingWindowFunc():
    sym_enc_setting_window = SymEncSettingWindow()
    
    while True:
        sym_enc_setting_event, sym_enc_setting_values = sym_enc_setting_window.read()
        
        if sym_enc_setting_event in (Psg.WIN_CLOSED, "Exit"):
            break
        
        if sym_enc_setting_event == "Submit":
            eval(POPUP)
    
    sym_enc_setting_window.close()


def SymMenuWindowFunc():
    sym_menu_window = SymMenuWindow()
    
    while True:
        event2, values2 = sym_menu_window.read()
        if event2 in (Psg.WIN_CLOSED, "Exit"):
            break
        if event2 == SYM_MENU_BUTTONS[0]:
            SymAuthEncWindowFunc()
        
        elif event2 == SYM_MENU_BUTTONS[1]:
            SymUnauthEncWindowFunc()
        
        elif event2 == SYM_MENU_BUTTONS[2]:
            SymAuthDecWindowFunc()
        
        elif event2 == SYM_MENU_BUTTONS[3]:
            SymUnAuthDecWindowFunc()
        
        elif event2 == "Settings":
            SymSettingWindowFunc()
        
        elif event2 == "SymAlgoUpdate":
            print(values2['SymAlgo'])
    
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
