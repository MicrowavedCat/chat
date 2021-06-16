# Chat client/Serveur TCP/UDP

Ce projet est issu du projet 1. C'est un chat client/serveur, permettant la communication TCP et UDP en même temps.

### Prérequis 
Le client nécessite la librairie ncurses

# Compilation
Placez-vous à la racine du projet.

## Client
Pour compiler le client, utilisez :
```bash
gcc client.c -o client -lcurses
```

## Serveur
Pour compiler le serveur, utilisez :
```bash
gcc serveur.c -o serveur
```

# Execution
Placez-vous à la racine du projet.

## Client
Pour lancer le client, utilisez :
```bash
./client <arguments>
``` 

Les arguments suivants sont disponibles :
|Argument|Description|Obligatoire|Valeur par défaut|
|------------|------------|------------|------------|
|-i|Adresse ipv4 de connexion au serveur|Oui||
|-l|Pseudo|Oui||
|-p|Port de connexion au serveur|Oui||
|-t|Lancer le client en TCP|Oui||
|-u|Lancer le client en UDP|Oui||

## Serveur
Pour lancer le serveur, utilisez :
```bash
./serveur <arguments>
``` 

Les arguments suivants sont disponibles :
|Argument|Description|Obligatoire|Valeur par défaut|
|------------|------------|------------|------------|
|-m|Nombre maximum de clients|Non|100|
|-p|Port d'écoute|Non|2021|
