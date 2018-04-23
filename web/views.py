from django.http import Http404
from django.views.generic import ListView, FormView, DeleteView, CreateView, UpdateView
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, get_object_or_404
import django.http as http
from django.core.urlresolvers import reverse

import datetime

from django.http import HttpResponse
from django.contrib import auth
import json
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
# from woocommerce import API


class Index(CreateView):
    template_name = 'web/index.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {})

# class Tienda(CreateView):
#     template_name ='web/tienda.html'
#
#     def get(self, request, *args, **kwargs):
#         wcapi = API(
#             url="http://192.168.1.23/universitarios",
#             consumer_key="ck_05794192f802627efa1d145bedb4088a4bc97263",
#             consumer_secret="cs_c591a9e5ef4a44b3b266cc6c5eb9ff3bf5e55be5"
#         )
#         print(wcapi.get("products").json())
#         return render(request, self.template_name, {})

