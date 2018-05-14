
from django.conf.urls import patterns, include,url
from django.contrib.auth.decorators import login_required
from usuarios import views

urlpatterns = [

     url(r'^administradores/$', login_required(views.AdministradoresList.as_view()), name='administradores_list'),
     url(r'^clientes/$', login_required(views.ClientesList.as_view()), name='clientes_list'),
     url(r'^autocompletado/$', login_required(views.UsuarioAutocomplete.as_view()), name='usuario_autocomplete'),
     url(r'^crear/$', login_required(views.UsuarioCreate.as_view()), name='usuario_create'),
     url(r'^borrar/(?P<pk>\d+)$', login_required(views.UsuarioDelete.as_view()) , name='usuario_delete'),
     url(r'^editar/(?P<pk>\d+)$', login_required(views.UsuarioEdit.as_view()) , name='usuario_edit'),
     url(r'^java/', include('usuarios.urls_java')),
]