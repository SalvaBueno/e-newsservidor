# -*- coding:utf-8 -*-

__copyright__ = 'Copyright 2016, Dreams Apps Creative'

from django.core.management import BaseCommand
from usuarios.models import Sesion,Grupo, User
from notificaciones.models import Notificacion
from annoying.functions import get_object_or_None
from configuracion import settings

import json


class Command(BaseCommand):
    args = '<ruta hasta el CSV>'
    help = 'importar csv'
    activo = False
    cola = []
    id_fin = 0

    def handle(self, *args, **options):
        import datetime
        hay_ruta = False
        ruta = ""

        for arg in args:
            if arg.find("ruta=") > -1:
                hay_ruta = True
                ruta = arg[5:]

        if hay_ruta:
            import csv
            file = open(ruta, 'rb')
            reader = csv.reader(file, delimiter=";")
            for row in reader:
                if row[0]!="Name":
                    try:
                        telefono = row[4].replace("+34", "")
                        telefono = telefono.replace(" ", "")
                        usuario = get_object_or_None(User, username=telefono)
                        if usuario is None:
                            usuario = get_object_or_None(User, username=row[4])
                            if usuario is None:
                                usuario = User.objects.create_user(telefono, row[5], "1234")
                            else:
                                usuario.username = telefono
                        usuario.first_name = row[1] +" "+ row[2]
                        usuario.last_name = row[3]
                        usuario.save()
                    except Exception as e:
                        print "Error en "+ row[0]


