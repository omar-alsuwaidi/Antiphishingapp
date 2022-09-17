from django.shortcuts import render
from django.http import JsonResponse
import pandas as pd
from .models import PredResults
from .models import Legitimate
from .models import Phishing
import numpy as np
import pickle
import xgboost
from URLFeatureExtraction import *


def antphishing(request):
    return render(request, 'predict.html')


def cats(series):
    return pd.Series(np.where(series == 0, "Legitimate Website", "Phishing Website"))


def predict_phishing(request):

    if request.POST.get('action') == 'post':

        # Receive data from client
        url_inputs = str(request.POST.get('url_input'))

        # Unpickle model
        # loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))
        loaded_model = pd.read_pickle("XGBoostClassifier.pickle")
        # feature names
        feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                         'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                         'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click',
                         'Web_Forwards']

        data = pd.DataFrame(columns=feature_names)
        data.loc[0] = featureExtraction(url_inputs)
        data = data.apply(pd.to_numeric)
        # Make prediction
        result = loaded_model.predict(data)

        classification = cats(result)[0]
        Domain = getDomain(url_inputs)
        Have_IP = int(data['Have_IP'][0])
        Have_At = int(data['Have_At'][0])
        URL_Length = int(data['URL_Length'][0])
        URL_Depth = int(data['URL_Depth'][0])
        Redirection = int(data['Redirection'][0])
        https_Domain = int(data['https_Domain'][0])
        TinyURL = int(data['TinyURL'][0])
        Prefix_Suffix = int(data['Prefix/Suffix'][0])
        DNS_Record = int(data['DNS_Record'][0])
        Web_Traffic = int(data['Web_Traffic'][0])
        Domain_Age = int(data['Domain_Age'][0])
        Domain_End = int(data['Domain_End'][0])
        iFrame = int(data['iFrame'][0])
        Mouse_Over = int(data['Mouse_Over'][0])
        Right_Click = int(data['Right_Click'][0])
        Web_Forwards = int(data['Web_Forwards'][0])

        PredResults.objects.create(Domain=Domain, Have_IP=Have_IP, Have_At=Have_At, URL_Length=URL_Length,
                                   URL_Depth=URL_Depth, Redirection=Redirection, https_Domain=https_Domain,
                                   TinyURL=TinyURL, Prefix_Suffix=Prefix_Suffix, DNS_Record=DNS_Record,
                                   Web_Traffic=Web_Traffic, Domain_Age=Domain_Age, Domain_End=Domain_End,
                                   iFrame=iFrame, Mouse_Over=Mouse_Over, Right_Click=Right_Click,
                                   Web_Forwards=Web_Forwards, classification=classification)

        return JsonResponse({'result': classification, 'Domain': Domain,
                             'Have_IP': Have_IP,'Have_At':Have_At, 'URL_Length':URL_Length,
                             'URL_Depth': URL_Depth, 'Redirection':Redirection,
                             'https_Domain': https_Domain, 'TinyURL': TinyURL,
                             'Prefix_Suffix': Prefix_Suffix, 'DNS_Record':DNS_Record,
                             'Web_Traffic': Web_Traffic,'Domain_Age': Domain_Age,
                             'Domain_End': Domain_End, 'iFrame': iFrame,
                             'Mouse_Over': Mouse_Over, 'Right_Click': Right_Click,'Web_Forwards': Web_Forwards},
                            safe=False)


def view_results(request):
    # Submit prediction and show all
    data = {"dataset": PredResults.objects.all()}
    return render(request, "results.html", data)


def view_legitimate(request):
    leg = pd.read_csv(r"3.legitimate.csv")
    leg['Label'] = cats(leg['Label'])
    leg.rename(columns={'Prefix/Suffix': 'Prefix_Suffix'}, inplace=True)
    leg = leg.to_dict('records')

    model_instances = [Legitimate(
        Domain=record['Domain'],
        Have_IP=record['Have_IP'],
        Have_At=record['Have_At'],
        URL_Length=record['URL_Length'],
        URL_Depth=record['URL_Depth'],
        Redirection=record['Redirection'],
        https_Domain=record['https_Domain'],
        TinyURL=record['TinyURL'],
        Prefix_Suffix=record['Prefix_Suffix'],
        DNS_Record=record['DNS_Record'],
        Web_Traffic=record['Web_Traffic'],
        Domain_Age=record['Domain_Age'],
        Domain_End=record['Domain_End'],
        iFrame=record['iFrame'],
        Mouse_Over=record['Mouse_Over'],
        Right_Click=record['Right_Click'],
        Web_Forwards=record['Web_Forwards'],
        Label=record['Label'],
    ) for record in leg]
    Legitimate.objects.bulk_create(model_instances)

    # Submit prediction and show all
    data_leg = {"dataset1": Legitimate.objects.all()}
    return render(request, "legitimate.html", data_leg)

def view_phishing(request):
    phis = pd.read_csv(r"4.phishing.csv")
    phis['Label'] = cats(phis['Label'])
    phis.rename(columns={'Prefix/Suffix': 'Prefix_Suffix'}, inplace=True)
    phis = phis.to_dict('records')

    model_instances1 = [Phishing(
        Domain=record['Domain'],
        Have_IP=record['Have_IP'],
        Have_At=record['Have_At'],
        URL_Length=record['URL_Length'],
        URL_Depth=record['URL_Depth'],
        Redirection=record['Redirection'],
        https_Domain=record['https_Domain'],
        TinyURL=record['Tiny_URL'],
        Prefix_Suffix=record['Prefix_Suffix'],
        DNS_Record=record['DNS_Record'],
        Web_Traffic=record['Web_Traffic'],
        Domain_Age=record['Domain_Age'],
        Domain_End=record['Domain_End'],
        iFrame=record['iFrame'],
        Mouse_Over=record['Mouse_Over'],
        Right_Click=record['Right_Click'],
        Web_Forwards=record['Web_Forwards'],
        Label=record['Label'],
    ) for record in phis]
    Phishing.objects.bulk_create(model_instances1)


    # Submit prediction and show all
    data_phis = {"dataset2": Phishing.objects.all()}
    return render(request, "phishing.html", data_phis)