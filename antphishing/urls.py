from django.urls import path
from . import views

app_name = "antphishing"

urlpatterns = [
    path('', views.antphishing, name='prediction_page'),
    path('predict/', views.predict_phishing, name='submit_prediction'),
    path('results/', views.view_results, name='results'),
    path('legitimate/', views.view_legitimate, name='legitimate'),
    path('phishing/', views.view_phishing, name='phishing'),
    ]