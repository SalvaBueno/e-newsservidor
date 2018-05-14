# -*- encoding: utf-8 -*-

__author__ = 'salva'

from configuracion import settings
from django.core.mail import EmailMessage


def enviar_email(asunto, mensaje, mensaje_html, destinos):
    msg = EmailMessage(asunto, mensaje_html, settings.EMAIL_HOST_USER, destinos)
    msg.content_subtype = "html"
    msg.send()
