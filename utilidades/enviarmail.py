# -*- encoding: utf-8 -*-
__author__ = 'brian'

import smtplib
import mimetypes
import commands

from configuracion import settings

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage


def enviarmail(texto,asunto,destinatario):

    # Construimos el mensaje simple
    mensaje = MIMEMultipart
    mensaje['From'] = "dreamsappscreative@gmail.com"
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto

    mensaje.attach(MIMEText(texto))


    # Establecemos conexion con el servidor smtp de gmail
    mailServer = smtplib.SMTP('smtp.gmail.com',587)
    mailServer.ehlo()
    mailServer.starttls()
    mailServer.ehlo()
    mailServer.login("dreamsappscreative@gmail.com","BETA500BANANA")

    # Envio del mensaje
    mailServer.sendmail("dreamsappscreative@gmail.com",
                    destinatario,
                    mensaje.as_string())

    # Cierre de la conexion
    mailServer.close()

'''
metodo para enviar un email a traves de smtp
'''
def enviarmailcompuesto(texto,asunto,destinatario):

    # Construimos el mensaje simple
    mensaje = MIMEMultipart()
    mensaje['From'] = "brayanbermudez@dreamsappscreative.es"
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto

    # adjuntamos el texto que necesitemos
    mensaje.attach(MIMEText(texto,'html'))

    #vemos los archivos que se han subido y los adjuntamos
    try:
        res = commands.getoutput("ls "+settings.MEDIA_ROOT+"/archivos_correos")
        lista = res.split("\n")
        if len(lista)>0:
            for afile in lista:
                # Adjuntamos la imagen
                file = open(settings.MEDIA_ROOT+"/archivos_correos/"+afile, "rb")
                contenido = MIMEImage(file.read())
                contenido.add_header('Content-Disposition', 'attachment; filename = afile')
                mensaje.attach(contenido)
    except Exception as e:
        print "no se adjuntan archivos"


    # Establecemos conexion con el servidor smtp de gmail
    mailServer = smtplib.SMTP('smtp.dreamsappscreative.es',587)
    mailServer.ehlo()
    mailServer.starttls()
    mailServer.ehlo()
    mailServer.login("brayanbermudez@dreamsappscreative.es","Riejumrx50")

    # Envio del mensaje
    mailServer.sendmail("brayanbermudez@dreamsappscreative.es",
                    destinatario,
                    mensaje.as_string())

    # Cierre de la conexion
    mailServer.close()

