# -*- coding: utf-8 -*-

from django.conf.urls import include, url
from django.contrib.auth import views as auth_views
from configuracion import views as configuracion_views
from configuracion import views as web_views
from django.contrib import admin

admin.autodiscover()

urlpatterns = [

    url(r'^$', web_views.Index.as_view(), name='inicio'),
    url(r'^login/$', configuracion_views.ajax_login, name='login'),
    url(r'^logout/$', configuracion_views.ajax_logout, name='logout'),
    url(r'password_change/$', auth_views.password_change, {'template_name': 'cambiar_pass.html'},
        name='password_change'),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^usuarios/', include('usuarios.urls')),
    url(r'^enews/', include('enews.urls_java')),
    url(r'^ckeditor/', include('ckeditor_uploader.urls')),
]

# if settings.DEBUG:
# import debug_toolbar
# urlpatterns += patterns('',
#    url(r'^__debug__/', include(debug_toolbar.urls)),
# )
