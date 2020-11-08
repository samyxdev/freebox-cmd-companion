"""
CONNEXION ETABLIE, USAGE DE FONCTION POSSIBLE: VOIR EXEMPLE

WIP Now: Ajouter la detection d'une session déjà existante pour ne pas en créer en trop

ToDo:
x Lire l'appToken et le trackId d'un fichier (pour éviter d'avoir trop de requetes obsoletes)
- Passage en classes et fonctions
x Ajout d'un statut de connexion à la FBX (connected)
- Ajout du "Track authorization progress", voir API Freebox
- Ajout de la première fonction : Activer ou désactiver le wifi
- Ajouter la detection d'une session déjà existante pour ne pas en créer en trop
- Creer un dictionnaire avec toutes les requetes utilisées

Info:
D'après l'API à propos de la connection/mise en place d'une session:
	Then the app will need to open a session to get an auth_token. 
	The app will then be authenticated by adding this session_token in HTTP headers of the following requests. 
	The validity of the auth_token is limited in time and the app will have to renew this auth_token once in a while.

Pour se connecter:
	- Recuperer un app_token (Sorte d'API key)
	- Puis recuperer un challenge
	- Renvoyer un hmac sha1 de challenge + app_token
	- Recevoir un session_token

"""
import requests, json, hmac, hashlib, binascii, time, pickle

delaiAttente = 5
needToken = True
tryReadData = False
appToken = None
connected = False

appToken = None
trackId = ""

nameFile = "data"

ip = "88.172.170.138"
prefixReq = "http://" + ip + "/api/v3"

infoToken = {"app_id": "fr.freebox.apppython",
   "app_name": "Python Yekohat",
   "app_version": "0.0",
   "device_name": "YekoWIN"}

#Header a passer pour appel d'API
sessionHeader = {"X-Fbx-App-Auth":None}

if(input("Voulez-vous essayer de lire des données du fichier \""+ nameFile +"\" (Oui par défaut)") == ""):
	tryReadData = True
else:
	tryReadData = False

if(tryReadData == True):
	#On essaye d'abord de trouver le trackId et l'appToken dans le fichier data
	noData = True
	try:
		with open(nameFile, "rb") as f:
			pikle = pickle.Unpickler(f)
			dataReaded = pikle.load()

			if("appToken" in dataReaded):
				print("Les informations ont été récupérée d'après la précédente requête sauvgardée.",
					"\n Données: ", dataReaded)

				appToken, trackId = dataReaded["appToken"], dataReaded["trackId"]

				noData = False
				needToken = False

				print("App Token: " + appToken)

			else:
				print("Aucune information n'a pu être récupérée d'après le fichier.")
				noData = True
	except:
		print("Erreur lors de la lecture des données.")
		noData = True
		
	if(noData):
		if(input("Voulez-vous faire une requête de clé ? (Oui par défaut)") == ""):
			needToken = True


#Si l'utilisateur a essayé de lire dans le fichier et que ca n'a pas marché OU qu'il a demandé une req 
if(needToken == True or tryReadData == False):
	tokenRequest = requests.post(prefixReq + "/login/authorize/", data = json.dumps(infoToken))

	print("TokenRequest reponse: ", tokenRequest.text)

	if(json.loads(tokenRequest.text)["success"] == True):
		h = json.loads(tokenRequest.text)["result"]
		appToken = h["app_token"]
		print("La requête à été reçue avec succès. Clé: ", appToken)

		trackId = str(h["track_id"])

		print("Vous avez ", delaiAttente, "sec pour accepter la requête sur l'écran de votre freebox.")
		time.sleep(delaiAttente)

		#Enregistrer les appToken et trackId dans un fichier
		if(input("Enregistrer l'appToken et le trackId dans le fichier data ? (Oui par défaut)") == ""):
			try:
				with open(nameFile, "wb") as f:
					pick = pickle.Pickler(f)
					pick.dump({"appToken":appToken, "trackId":trackId})
				print("Les données ont été sauvgardées avec succès.")

			except:
				print("Une erreur est survenue lors de l'enregistrement des données.")

	else:
		print("La requête à échouée.")
		appToken = None


#Si on a token, soit donné par nous même, soit donné par le if(needToken == True)
if(appToken != None or appToken == ""):
	#Track progress
	trackReq = requests.get(prefixReq + "/login/authorize/" + trackId)
	print("TrackReq reponse: ", trackReq.text)

	#Recuperation challenge
	challengeRequest = requests.get(prefixReq + "/login/")

	raw = json.loads(challengeRequest.text)["result"]
	challenge = raw["challenge"]

	hashed = hmac.new(appToken.encode(), challenge.encode(), hashlib.sha1)
	passSession = binascii.hexlify(hashed.digest())

	#D'après la doc freebox, passSession doit etre un HMAC SHA-1 du token + challenge
	sessionReqData = {"app_id":infoToken["app_id"], "password":passSession.decode()}
	print("Token: ", appToken, " \nChallenge: ", challenge, "\nPass: ", passSession.decode())

	print("SessionReqData: ", sessionReqData)
	sessionRequest = requests.post(prefixReq + "/login/session/", data = json.dumps(sessionReqData))
	print("SessionReq result: ", sessionRequest.text)

	sessionToken = json.loads(sessionRequest.text)["result"]["session_token"]
	print("Le sessionToken est ", sessionToken)

	#Mise a jour du sessionHeader
	sessionHeader["X-Fbx-App-Auth"] = sessionToken

	trackAuth = requests.get(prefixReq + "/login/authorize/" + trackId)
	print("Debug track auth: ", trackAuth.text)

	#Tentative de connection mais ne semble pas marcher
	"""
	headersSupp = {"X-Fbx-App-Auth":sessionToken}
	connectionRequest = requests.get(ip + "/api/v3/login/session/", headers=headersSupp)

	print("ConnectionReq result: ", connectionRequest.text)
	"""

	#Une autre tentative de connexion - Permet aussi de savoir si on est connecté
	connectionRequest = requests.get(prefixReq + "/login/", headers = sessionHeader)

	print("ConnectionReq result: ", connectionRequest.text)

	connected = json.loads(connectionRequest.text)["result"]["logged_in"]

	if(connected == True):
		print("Vous vous êtes connecté avec succés.")
	else:
		print("La connection n'a pas été établie.")


	#Exemple de fonction simple: Get Download Stats
	dwStatsRequest = requests.get(prefixReq + "/downloads/stats", headers = sessionHeader)
	print("Download stats: ", dwStatsRequest.text)
	#Fin fonction

#Fin d'exécution
if(connected == True):
	print("Fin d'éxecution. Le programme va se déconnecter.")

	logoutRequest = requests.post(prefixReq + "/login/logout/", headers = sessionHeader)
	print("LogoutReq result: ", logoutRequest.text)




