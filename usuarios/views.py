# -*- encoding: utf-8 -*-

from models import User
import forms, models
from dal import autocomplete
from django.views.generic import ListView, FormView, DeleteView, CreateView, UpdateView
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, get_object_or_404
from annoying.functions import get_object_or_None
import django.http as http
from django.core.urlresolvers import reverse

import datetime

from django.http import HttpResponse
from django.contrib import auth
import json
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q



class AdministradoresList(CreateView):

    template_name = 'usuarios/administradores_list.html'

    def get(self, request, *args, **kwargs):
        usuarios = User.objects.filter(is_staff=1).order_by('id')
        return render(request, self.template_name, {'usuarios': usuarios,
                                                    })


class ClientesList(ListView):
    template_name = 'usuarios/trabajadores_list.html'

    def get(self, request, *args, **kwargs):
        usuarios = User.objects.filter(is_staff=0).order_by('id')
        return render(request, self.template_name, {'usuarios': usuarios,
                                                    })


class UsuarioAutocomplete(autocomplete.Select2QuerySetView):
    def get_queryset(self):
        # Don't forget to filter out results depending on the visitor !
        if not self.request.user.is_authenticated():
            return User.objects.none()

        qs = User.objects.all()
        if self.q:
            qs = qs.filter(Q(username__icontains=self.q) | Q(first_name__icontains=self.q))

        return qs


class UsuarioCreate(FormView):
    template_name = 'usuarios/usuario_create.html'
    form_class = forms.UsuarioForm

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)

        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        data = request
        form = forms.UsuarioForm(data.POST)

        if form.is_valid():
            usuario = form.save()
            usuarios = User.objects.all().order_by('id')

            if usuario.is_staff:
                return http.HttpResponseRedirect(reverse('administradores_list'))
            else:
                return http.HttpResponseRedirect(reverse('clientes_list'))

        return render(request, self.template_name, {
            'form': form,

        })


class UsuarioEdit(FormView):
    template_name = 'usuarios/usuario_editar.html'
    form_class = forms.UsuarioEditForm

    def get(self, request, *args, **kwargs):

        usuario = get_object_or_404(User, pk=self.kwargs['pk'])

        form = self.form_class(usuario=usuario)

        return render(request, self.template_name, {'usuario': usuario, 'form': form})

    def post(self, request, *args, **kwargs):
        data = request
        usuario = get_object_or_404(User, pk=self.kwargs['pk'])
        form = self.form_class(data.POST, usuario=usuario)

        if form.is_valid():
            usuario = form.save()
            if usuario.is_staff:
                return http.HttpResponseRedirect(reverse('administradores_list'))
            else:
                return http.HttpResponseRedirect(reverse('clientes_list'))
        return render(request, self.template_name, {'usuario': usuario, 'form': form})


class UsuarioDelete(DeleteView):
    template_name = 'usuarios/usuario_delete.html'
    form_class = forms.ContrasenaForm

    def get(self, request, *args, **kwargs):

        form = self.form_class()

        usuario = get_object_or_404(models.User, pk=self.kwargs['pk'])
        return render(request, self.template_name, {'usuario': usuario, 'form':form})

    def post(self, request, *args, **kwargs):
        usuario = get_object_or_404(models.User, pk=self.kwargs['pk'])
        form = self.form_class(request.POST)
        password = form['contrasena'].value()
        correcto = request.user.check_password(password)
        if correcto:
            if usuario.is_staff:
                usuario.delete()
                return http.HttpResponseRedirect(reverse('administradores_list'))
            else:
                usuario.delete()
                return http.HttpResponseRedirect(reverse('clientes_list'))
        else:
            return render(request, self.template_name, {'usuario': usuario ,'form':form})







