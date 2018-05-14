from django.contrib import admin
from enews import models
admin.site.register(models.Categoria)
admin.site.register(models.Noticia)
admin.site.register(models.Comentario)

# Register your models here.
