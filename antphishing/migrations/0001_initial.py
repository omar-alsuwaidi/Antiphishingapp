# Generated by Django 4.1.1 on 2022-09-17 07:38

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Legitimate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Domain', models.CharField(max_length=1000)),
                ('Have_IP', models.FloatField()),
                ('Have_At', models.FloatField()),
                ('URL_Length', models.FloatField()),
                ('URL_Depth', models.FloatField()),
                ('Redirection', models.FloatField()),
                ('https_Domain', models.FloatField()),
                ('TinyURL', models.FloatField()),
                ('Prefix_Suffix', models.FloatField()),
                ('DNS_Record', models.FloatField()),
                ('Web_Traffic', models.FloatField()),
                ('Domain_Age', models.FloatField()),
                ('Domain_End', models.FloatField()),
                ('iFrame', models.FloatField()),
                ('Mouse_Over', models.FloatField()),
                ('Right_Click', models.FloatField()),
                ('Web_Forwards', models.FloatField()),
                ('Label', models.CharField(max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='Phishing',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Domain', models.CharField(max_length=1000)),
                ('Have_IP', models.FloatField()),
                ('Have_At', models.FloatField()),
                ('URL_Length', models.FloatField()),
                ('URL_Depth', models.FloatField()),
                ('Redirection', models.FloatField()),
                ('https_Domain', models.FloatField()),
                ('TinyURL', models.FloatField()),
                ('Prefix_Suffix', models.FloatField()),
                ('DNS_Record', models.FloatField()),
                ('Web_Traffic', models.FloatField()),
                ('Domain_Age', models.FloatField()),
                ('Domain_End', models.FloatField()),
                ('iFrame', models.FloatField()),
                ('Mouse_Over', models.FloatField()),
                ('Right_Click', models.FloatField()),
                ('Web_Forwards', models.FloatField()),
                ('Label', models.CharField(max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='PredResults',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Domain', models.CharField(max_length=1000)),
                ('Have_IP', models.FloatField()),
                ('Have_At', models.FloatField()),
                ('URL_Length', models.FloatField()),
                ('URL_Depth', models.FloatField()),
                ('Redirection', models.FloatField()),
                ('https_Domain', models.FloatField()),
                ('TinyURL', models.FloatField()),
                ('Prefix_Suffix', models.FloatField()),
                ('DNS_Record', models.FloatField()),
                ('Web_Traffic', models.FloatField()),
                ('Domain_Age', models.FloatField()),
                ('Domain_End', models.FloatField()),
                ('iFrame', models.FloatField()),
                ('Mouse_Over', models.FloatField()),
                ('Right_Click', models.FloatField()),
                ('Web_Forwards', models.FloatField()),
                ('classification', models.CharField(max_length=30)),
            ],
        ),
    ]
