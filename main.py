import telebot
from csrlib import token, convert, csrCheck
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

bot = telebot.TeleBot(token)
botWelcomeMessage = 'Привет!\nДля декодинга .CSR файла просто пришли его мне!'


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, botWelcomeMessage)


@bot.message_handler(content_types=['document'])
def send_csr_decode(message):
    try:
        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        print('Checking CSR...')

        if csrCheck(downloaded_file, file_info):
            req = load_certificate_request(FILETYPE_PEM, downloaded_file)
            key = req.get_pubkey()
            key_type = 'RSA' if key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
            subject = req.get_subject()
            components = dict(subject.get_components())
            str_components = convert(components)
            bot.reply_to(message, f"Common name: {str_components ['CN']}\n"
                                  f"Organisation: {str_components ['O']}\n"
                                  f"State/province: {str_components ['ST']}\n"
                                  f"Country: {str_components ['C']}\n"
                                  f"Key algorithm: {key_type}\n"
                                  f"Key size: {key.bits()}")
            bot.reply_to(message, convert(downloaded_file).splitlines())
           
    except Exception as e:
        bot.reply_to(message, e)


if __name__ == '__main__':
    bot.infinity_polling()
