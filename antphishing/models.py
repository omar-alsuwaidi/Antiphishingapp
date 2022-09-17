from django.db import models


class PredResults(models.Model):

    Domain = models.CharField(max_length=1000)
    Have_IP = models.FloatField()
    Have_At = models.FloatField()
    URL_Length = models.FloatField()
    URL_Depth = models.FloatField()
    Redirection = models.FloatField()
    https_Domain = models.FloatField()
    TinyURL = models.FloatField()
    Prefix_Suffix = models.FloatField()
    DNS_Record = models.FloatField()
    Web_Traffic = models.FloatField()
    Domain_Age = models.FloatField()
    Domain_End = models.FloatField()
    iFrame = models.FloatField()
    Mouse_Over = models.FloatField()
    Right_Click = models.FloatField()
    Web_Forwards = models.FloatField()
    classification = models.CharField(max_length=30)

    def __str__(self):
        return self.classification


class Legitimate(models.Model):

    Domain = models.CharField(max_length=1000)
    Have_IP = models.FloatField()
    Have_At = models.FloatField()
    URL_Length = models.FloatField()
    URL_Depth = models.FloatField()
    Redirection = models.FloatField()
    https_Domain = models.FloatField()
    TinyURL = models.FloatField()
    Prefix_Suffix = models.FloatField()
    DNS_Record = models.FloatField()
    Web_Traffic = models.FloatField()
    Domain_Age = models.FloatField()
    Domain_End = models.FloatField()
    iFrame = models.FloatField()
    Mouse_Over = models.FloatField()
    Right_Click = models.FloatField()
    Web_Forwards = models.FloatField()
    Label = models.CharField(max_length=1000)

    def __str__(self):
        return self.Label


class Phishing(models.Model):

    Domain = models.CharField(max_length=1000)
    Have_IP = models.FloatField()
    Have_At = models.FloatField()
    URL_Length = models.FloatField()
    URL_Depth = models.FloatField()
    Redirection = models.FloatField()
    https_Domain = models.FloatField()
    TinyURL = models.FloatField()
    Prefix_Suffix = models.FloatField()
    DNS_Record = models.FloatField()
    Web_Traffic = models.FloatField()
    Domain_Age = models.FloatField()
    Domain_End = models.FloatField()
    iFrame = models.FloatField()
    Mouse_Over = models.FloatField()
    Right_Click = models.FloatField()
    Web_Forwards = models.FloatField()
    Label = models.CharField(max_length=1000)

    def __str__(self):
        return self.Label
