# -*- coding:utf-8 -*-

__copyright__ = 'Copyright 2016, Dreams Apps Creative'

from django.core.management import BaseCommand
from usuarios.models import Sesion,Grupo
from notificaciones.models import Notificacion
from annoying.functions import get_object_or_None
from configuracion import settings

import json


class Command(BaseCommand):
    args = ''
    help = 'crear las notificaciones para los usuarios'
    activo = False
    cola = []
    id_fin = 0

    def handle(self, *args, **options):
        import datetime
        hoy= datetime.date.today()
        manana = hoy + datetime.timedelta(days=1)
        sesiones = Sesion.objects.filter(dia__gte=hoy, dia__lte=manana)
        for ses in sesiones:
            print ses.grupo.nombre+" " + str(ses.dia)+" a las "+str(ses.grupo.hora_inicio)


            # comprobar que el estado sea normal o cambiado_no_permanente para notificar
            # cambiar colores de estados de sesion en la app (solo poner en texto y color de texto)
            # cambiar contraseña sin salir de la app
            # leyenda de colores en la web
            # numero de asistentes al grupo (negros+verdes) - (azules + rojos)       Asisten: X
            # contactar por whatsapp en vez de llamar en las sesiones que tenemos
            if ses.estado == "":
                pass


            if not ses.notificacion_dia_antes:
                print "se notifica para mañana"

                ses.notificacion_dia_antes=True
                ses.save()
                asunto = 'Recuerdatorio de tus sesiones'
                mensaje = str(ses.grupo.nombre) + ' ' + ses.grupo.dia_semana + ' a las ' + str(ses.grupo.hora_inicio)
                notificacion = Notificacion(usuario=ses.usuario, asunto=asunto, mensaje=mensaje)
                notificacion.save()
            elif not ses.notificacion_horas_antes:

                ahora = datetime.datetime.now()

                comparar =datetime.datetime.combine(ses.dia,ses.grupo.hora_inicio)

                if (comparar - ahora) < datetime.timedelta(hours=2):
                    print "usuario "+ses.usuario.username
                    ses.notificacion_dia_antes=True
                    ses.save()
                    asunto = 'Recuerdatorio de tus sesiones'
                    mensaje = str(ses.grupo.nombre) + ' ' + ses.grupo.dia_semana + ' a las ' + str(ses.grupo.hora_inicio)
                    notificacion = Notificacion(usuario=ses.usuario, asunto=asunto, mensaje=mensaje)
                    notificacion.save()

