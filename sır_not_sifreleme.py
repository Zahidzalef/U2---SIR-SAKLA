from tkinter import *
from tkinter import messagebox
import base64

FONT = ("Verdena",20,"normal")


def encode(key,clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c))%256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key,enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i])-ord(key_c))%256)
        dec.append(dec_c)
    return "".join(dec)


def notlari_sifrele():
    baslik = baslik_girisi.get()
    mesaj = giris_metni.get("1.0", END)
    sir = sifre_girdisi.get()

    if len(baslik) == 0 or len(mesaj) == 0 or len(sir)==0:
        messagebox.showinfo(title="HATA!",message="Lütfen işlemleri tamamlayınız.")
    else:
        sifreli_mesaj = encode(sir,mesaj)

        try:
            with open("not.txt","a") as dosya:
                # data_file.write(f'\n{title}\n{message_encrypted}')
                dosya.write("\n {} \n {}".format(baslik,sifreli_mesaj))
        except FileNotFoundError:
            with open("not.txt","w")as dosya:
                # data_file.write(f'\n{title}\n{message_encrypted}')
                dosya.write("\n {} \n {}".format(baslik,sifreli_mesaj))
        finally:
            baslik_girisi.delete(0, END)
            sifre_girdisi.delete(0, END)
            giris_metni.delete("1.0", END)



def sifreleri_coz():
    sifreli_mesaj = giris_metni.get("1.0", END)
    sir = sifre_girdisi.get()

    if len(sifreli_mesaj)==0 or len(sir)==0:
        messagebox.showinfo(title="HATA!",message="Lütfen işlemleri tamamlayınız!")
    else:
        try:
            ayriltilmis_mesaj = decode(sir,sifreli_mesaj)
            giris_metni.delete("1.0", END)
            giris_metni.insert("1.0", ayriltilmis_mesaj)
        except:
            messagebox.showinfo(title="HATA!",message="Lütfen şifrelenmiş bilgilerden emin olun.")



ekran = Tk()
ekran.title("SIR NOTU")
ekran.config(padx=35, pady=35)

baslik_bilgisi=Label(text="Başlık giriniz.", font=FONT)
baslik_bilgisi.pack()
baslik_girisi=Entry(width=30)
baslik_girisi.pack()
giris_bilgisi = Label(text="Sırı giriniz.", font=FONT)
giris_bilgisi.pack()
giris_metni = Text(width=50, height=25)
giris_metni.pack()
gizlenecek_not = Label(text="Şifreyi giriniz.", font=FONT)
gizlenecek_not.pack()
sifre_girdisi = Entry(width=30)
sifre_girdisi.pack()
kaydet_botunu = Button(text="Şifreleyin", command=notlari_sifrele)
kaydet_botunu.pack()
cozumleme_botunu = Button(text="Çözümleyin", command=sifreleri_coz)
cozumleme_botunu.pack()

ekran.mainloop()
