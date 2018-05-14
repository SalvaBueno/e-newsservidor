from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.db import models


class Categoria(models.Model):
    nombre_categoria = models.CharField(max_length=50)
    slug_nombre_categoria = models.CharField(max_length=50)
    descripcion_categoria = models.CharField(max_length=200)

    def __unicode__(self):
        return u"%s" % self.nombre_categoria


class Noticia(models.Model):
    categoria = models.ForeignKey(Categoria, null=True, blank=True)
    nombre_noticia = models.CharField(max_length=20)
    descripcion_noticia = models.CharField(max_length=300)
    titular_noticia = models.CharField(max_length=50)

    def __unicode__(self):
        return u"%s" % self.nombre_noticia


class Comentario(models.Model):
    noticia = models.ForeignKey(Noticia, null=True, blank=True)
    usuario = models.ForeignKey(User, null=True, blank=True)
    contenido_comentario = models.CharField(max_length=100)

    def __unicode__(self):
        return u"%s, %s" % self.pk, self.usuario.username
