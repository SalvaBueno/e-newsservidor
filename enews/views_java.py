# -*- encoding: utf-8 -*-
from enews.models import Noticia, Categoria
from enews.models import Comentario
from utilidades.contrasena import contrasena_generator

__author__ = 'salva'

import django.contrib.auth as auth
import django.http as http
from annoying.functions import get_object_or_None
from django.views.decorators.csrf import csrf_exempt
import json
import datetime
from utilidades import Token, enviarmail
from usuarios.models import Tokenregister, Usuario
from django.contrib.auth.models import User


def get_userdjango_by_token(datos):
    token = datos.get('token')
    user_token = Tokenregister.objects.get(token=token)
    return user_token.user


def get_userdjango_by_id(datos):
    userdjango_id = datos.get('usuario_id')
    userdjango = get_object_or_None(User, pk=userdjango_id)
    return userdjango


def comprobar_usuario(datos):
    userdjango = get_userdjango_by_id(datos)
    user_token = get_userdjango_by_token(datos)

    if (user_token is not None) and (userdjango is not None):
        if user_token == userdjango:
            return True
        else:
            return False


@csrf_exempt
def registrar_usuario(request):
    print "registrando usuario"
    try:
        datos = json.loads(request.POST['data'])
        nombre = datos.get('usuario')
        email = datos.get('email')
        password = datos.get('password')

        if (nombre is None and email is None and password is None) or (nombre == "" and password == "" and email == ""):
            response_data = {'result': 'error', 'message': 'Falta el nombre usuario, email y password'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        if nombre is None or nombre == "":
            response_data = {'result': 'error', 'message': 'Falta el nombre de usuario'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        if password is None or password == "":
            response_data = {'result': 'error', 'message': 'Falta el password'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        if email is None or email == "":
            response_data = {'result': 'error', 'message': 'Falta el email'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        usuarios = User.objects.filter(username=nombre)
        usuarios_email = User.objects.filter(email=email)

        if usuarios.count() == 0:
            if usuarios_email.count() == 0:
                user = User.objects.create(username=nombre, email=email)
                user.set_password(password)
                user.save()
                response_data = {'result': 'ok', 'message': 'Usuario creado correctamente'}
            else:
                response_data = {'result': 'error', 'message': 'Este email ya existe'}
        else:
            response_data = {'result': 'error', 'message': 'Este nombre de usuario ya existe'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except:
        response_data = {'errorcode': 'U0005', 'result': 'error', 'message': 'Error en crear usuario. ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def login(request):
    print "Login"
    try:
        datos = json.loads(request.POST['data'])
        us = datos.get('usuario').lower()
        password = datos.get('password')

        if (us is None and password is None) or (us == "" and password == ""):
            response_data = {'result': 'error', 'message': 'Falta el usuario y el password'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        if us is None or us == "":
            response_data = {'result': 'error', 'message': 'Falta el usuario'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        if password is None or password == "":
            response_data = {'result': 'error', 'message': 'Falta el password'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

        user = auth.authenticate(username=us, password=password)

        if user is not None:
            if user.is_active:
                user_token = get_object_or_None(Tokenregister, user=user)
                if user_token is None:
                    token1 = str(user.id) + "_" + Token.id_generator()
                    tokenform = Tokenregister(token=token1, user=user)
                    tokenform.save()
                    user_token = get_object_or_None(Tokenregister, user=user)
                else:
                    user_token.date = datetime.datetime.now()
                    user_token.token = str(user.id) + "_" + Token.id_generator()
                    user_token.save()

                response_data = {'result': 'ok', 'message': 'Usuario logueado', 'token': user_token.token,
                                 'usuario': user.username,
                                 'nombre': user.first_name,
                                 }

                return http.HttpResponse(json.dumps(response_data), content_type="application/json")

            else:
                response_data = {'result': 'error', 'message': 'Usuario no activo'}
                return http.HttpResponse(json.dumps(response_data), content_type="application/json")
        else:
            response_data = {'result': 'error', 'message': 'Usuario no válido'}
            return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0001', 'result': 'error', 'message': str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def logout(request):
    print "Logout"
    try:
        datos = json.loads(request.POST['data'])
        if comprobar_usuario(datos):
            userdjango = get_userdjango_by_token(datos)

            user_token = get_object_or_None(Tokenregister, user=userdjango)
            if user_token is None:
                response_data = {'result': 'ok', 'message': 'Usuario ya deslogueado'}
            else:

                user_token.delete()
                response_data = {'result': 'ok', 'message': 'Usuario ya deslogueado'}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0002', 'result': 'error', 'message': str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def comprobar_token(request):
    print "Comprobando token"
    try:
        datos = json.loads(request.POST['data'])
        token = datos.get('token')
        if token != "" and comprobar_usuario(datos):
            response_data = {'result': 'ok', 'message': 'Usuario logueado'}

        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0003', 'result': 'error', 'message': str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_perfil(request):
    print "buscando perfil"
    try:
        datos = json.loads(request.POST['data'])

        if comprobar_usuario(datos):
            userdjango = get_userdjango_by_token(datos)

            response_data = {'result': 'ok', 'message': 'Perfil de usuario',
                             'email': userdjango.email,
                             'username': userdjango.username,
                             'nombre': userdjango.first_name,
                             'apellidos': userdjango.last_name}

        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0004', 'result': 'error', 'message': 'Error en perfil de usuario: ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def cambiar_pass(request):
    print "cambiando pass"
    try:
        datos = json.loads(request.POST['data'])
        antiguapass = datos.get('antigua')
        nuevapass = datos.get('nueva')

        if comprobar_usuario(datos):
            userdjango = get_userdjango_by_token(datos)
            if userdjango.check_password(antiguapass):
                userdjango.set_password(nuevapass)
                userdjango.save()
                token = get_object_or_None(Tokenregister, user=userdjango)
                token.delete()
                response_data = {'result': 'ok', 'message': 'Password cambiado'}
            else:
                response_data = {'result': 'error', 'message': 'Password antiguo incorrecto'}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0005', 'result': 'error', 'message': 'Error en perfil de usuario: ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def recuperar_contrasena(request):
    try:
        try:
            datos = json.loads(request.POST['data'])
            username = datos.get('usuario')

        except Exception as e:
            username = request.POST['usuario']

        userdjango = get_object_or_None(User, username=username)
        if userdjango is not None:
            nueva_contrasena = contrasena_generator()
            userdjango.set_password(nueva_contrasena)

            userdjango.save()
            enviarmail.enviar_email("Contraseña nueva", "Se ha generado una nueva contraseña: " + nueva_contrasena,
                                    "Se ha generado una nueva contraseña: " + nueva_contrasena, [userdjango.email, ])

            response_data = {'result': 'ok', 'message': 'se ha enviado un email con la nueva contraseña'}

        else:
            response_data = {'result': 'error', 'message': 'usuario no existe'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0003', 'result': 'error', 'message': str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def cambiar_datos(request):
    print "cambiando pass"
    try:
        datos = json.loads(request.POST['data'])
        if comprobar_usuario(datos):
            userdjango = get_userdjango_by_token(datos)
            userdjango.first_name = datos.get('nombre')
            userdjango.last_name = datos.get('apellidos')
            userdjango.email = datos.get('email')
            userdjango.save()
            response_data = {'result': 'ok', 'message': 'Datos cambiados'}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0007', 'result': 'error', 'message': 'Error en perfil de usuario: ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_usuarios(request):
    print "buscando usuarios"
    try:
        response_data = {'result': 'ok', 'message': 'Listado de usuarios', 'usuarios': []}
        usuarios = User.objects.all().order_by('id')
        for a in usuarios:
            response_data['usuarios'].append({'pk': a.pk, 'username': a.username, 'email': a.email, })

        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en busqueda de usuarios : ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_comentarios(request):
    print "buscando comentarios"
    try:
        try:
            datos = json.loads(request.POST['data'])
        except Exception as e:
            datos = None

        if datos is not None and comprobar_usuario(datos):
            userdjango = get_userdjango_by_token(datos)
            comentarios = Comentario.objects.filter(usuario=userdjango).order_by("-pk")
            response_data = {'result': 'ok', 'message': 'Obtenemos las noticias', 'comentarios': []}
            for p in comentarios:
                if p.fecha_comentario is not None:
                    response_data['comentarios'].append({'pk': str(p.pk),
                                                         'contenido_comentario': p.contenido_comentario,
                                                         'fecha_comentario': str(p.fecha_comentario.day) + '/' + str(p.fecha_comentario.month) + '/' + str(p.fecha_comentario.year),
                                                         'noticia': {'pk': p.noticia.pk,
                                                                     'nombre_noticia': p.noticia.nombre_noticia},
                                                         'usuario': {'username': p.usuario.username}
                                                         })
                else:
                    response_data['comentarios'].append({'pk': str(p.pk),
                                                         'contenido_comentario': p.contenido_comentario,
                                                         'noticia': {'pk': p.noticia.pk,
                                                                     'nombre_noticia': p.noticia.nombre_noticia},
                                                         'usuario': {'username': p.usuario.username}
                                                         })
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        print response_data
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en la busqueda de comentarios : ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_noticias(request):
    print "buscando noticias"
    try:
        try:
            datos = json.loads(request.POST['data'])
            categoria_noticia = datos.get('categoria_noticia')
        except Exception as e:
            datos = None
            categoria_noticia = request.POST['categoria_noticia']

        if datos is not None and comprobar_usuario(datos):
            categoria = get_object_or_None(Categoria, nombre_categoria=categoria_noticia)
            noticias = Noticia.objects.filter(categoria=categoria).order_by("pk") if categoria is not None else None
            response_data = {'result': 'ok', 'message': 'Obtenemos las noticias', 'noticias': []}
            for p in noticias:
                if p.fecha_noticia is not None:
                    response_data['noticias'].append({'pk': str(p.pk),
                                                      'nombre_noticia': p.nombre_noticia,
                                                      'resumen_noticia': p.resumen_noticia,
                                                      'titular_noticia': p.titular_noticia,
                                                      'fecha_noticia': str(p.fecha_noticia.day) + '/' + str(p.fecha_noticia.month) + '/' + str(p.fecha_noticia.year),
                                                      'imagen_noticia': str(p.imagen_noticia)})
                else:
                    response_data['noticias'].append({'pk': str(p.pk),
                                                      'nombre_noticia': p.nombre_noticia,
                                                      'resumen_noticia': p.resumen_noticia,
                                                      'titular_noticia': p.titular_noticia,
                                                      'imagen_noticia': str(p.imagen_noticia)})
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        print response_data
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en la busqueda de noticias : ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_noticia(request):
    print "buscando noticia"
    try:
        try:
            datos = json.loads(request.POST['data'])
            noticia_pk = datos.get('noticia_pk')

        except Exception as e:
            datos = None
            noticia_pk = request.POST['noticia_pk']

        if datos is not None and comprobar_usuario(datos):
            noticia = get_object_or_None(Noticia, pk=noticia_pk)
            if noticia.fecha_noticia is not None:
                response_data = {'result': 'ok', 'pk': str(noticia.pk),
                                  'nombre_noticia': noticia.nombre_noticia,
                                  'resumen_noticia': noticia.resumen_noticia,
                                  'descripcion_noticia': noticia.descripcion_noticia,
                                  'titular_noticia': noticia.titular_noticia,
                                  'fecha_noticia': str(noticia.fecha_noticia.day) + '/' + str(
                                      noticia.fecha_noticia.month) + '/' + str(noticia.fecha_noticia.year),
                                  'imagen_noticia': str(noticia.imagen_noticia)}
            else:
                response_data = {'result': 'ok', 'pk': str(noticia.pk),
                                  'nombre_noticia': noticia.nombre_noticia,
                                  'resumen_noticia': noticia.resumen_noticia,
                                  'descripcion_noticia': noticia.descripcion_noticia,
                                  'titular_noticia': noticia.titular_noticia,
                                  'imagen_noticia': str(noticia.imagen_noticia)}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

        print response_data
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en la busqueda de comentarios : ' + str(e)}
        return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def get_comentarios_noticia(request):
    print "buscando noticia"
    try:
        try:
            datos = json.loads(request.POST['data'])
            noticia_pk = datos.get('pk')

        except Exception as e:
            datos = None
            noticia_pk = request.POST['pk']

        if datos is not None and comprobar_usuario(datos):
            comentarios = Comentario.objects.filter(noticia__pk=noticia_pk)
            userdjango = get_userdjango_by_token(datos)

            if comentarios.count() > 0:
                response_data = {'result': 'ok', 'message': 'Obtenemos los comentarios de la noticia',
                                 'comentarios': []}
                for p in comentarios:
                    response_data['comentarios'].append({'pk': str(p.pk),
                                                         'usuario': userdjango.username,
                                                         'contenido_comentario': p.contenido_comentario,
                                                         })
            else:
                response_data = {'result': 'error', 'message': 'No hay comentarios para esta noticia'}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en la busqueda de comentarios : ' + str(e)}
    return http.HttpResponse(json.dumps(response_data), content_type="application/json")


@csrf_exempt
def registrar_comentarios(request):
    print "introduciendo comentario"
    try:
        try:
            datos = json.loads(request.POST['data'])
            noticia_pk = datos.get('pk')
            contenido_comentario = datos.get('contenido_comentario')
            noticia = get_object_or_None(Noticia, pk=noticia_pk)
        except Exception as e:
            datos = None
            noticia_pk = request.POST['pk']
            contenido_comentario = request.POST['contenido_comentario']
            noticia = get_object_or_None(Noticia, pk=noticia_pk)

        if datos is not None and comprobar_usuario(datos) and noticia is not None:
            userdjango = get_userdjango_by_token(datos)
            comentario = Comentario.objects.create(
                usuario=userdjango,
                noticia=noticia,
                contenido_comentario=contenido_comentario)
            comentario.save()

            response_data = {'result': 'ok', 'message': 'Comentarios añadido con exito'}
        else:
            response_data = {'result': 'error', 'message': 'Usuario no logueado'}

    except Exception as e:
        response_data = {'errorcode': 'U0006', 'result': 'error',
                         'message': 'Error en la busqueda de comentarios : ' + str(e)}
    return http.HttpResponse(json.dumps(response_data), content_type="application/json")
