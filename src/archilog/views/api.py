import logging
from urllib import request
from uuid import UUID

from flask import Flask, Blueprint, jsonify #Prérequis
from spectree import SpecTree, SecurityScheme, BaseFile
from pydantic import BaseModel, Field #Utilisation
from flask_httpauth import HTTPTokenAuth
import archilog.models as models

api = Blueprint("api", __name__, url_prefix="/api")
auth = HTTPTokenAuth(scheme="Bearer")
#------------------Authentification avec token sur Swagger-------------
#Validation automatique des donneés entrante, generation doc SWAGGER et securité TOkens
spec = SpecTree(
    "flask",
    security_schemes=[
        SecurityScheme(
            name="bearer_token", #nom de la sécurité
            data={"type":"http","scheme":"bearer"} #token de type Bearer
        )
    ],
    security=[{"bearer_token":  []}] # applique a toute les routes
)
#On veux proteger certaine routes avec des tokens de type Bearer


TOKENS = {
    "admin-token": "admin", #role admin
    "user-token": "user" #role user
}

#vérifiaction
@auth.verify_token
def verify_token(token):
    return TOKENS.get(token)



#-------------MODELS------------
class EntryInput(BaseModel):
    name: str = Field(min_length=2, max_length=100, description="Nom de l'entrée")
    amount: float = Field(gt=0, description="Montant de l'entrée")
    category: str | None = Field(default=None, description="Catégorie optionnelle")


#--------------------Route------------------
@api.route("/")  # Exiger la connexion via un token
def index():
    # Exemple d'affichage de données ou d'informations de l'API
    logging.info("Route /api/ a été atteinte")
    return jsonify(message="Bienvenue sur l'API de gestion des entrées ! Vous êtes connecté en tant que {}".format(auth.current_user())), 200

@api.route("/user", methods=["POST"])
@auth.login_required
@spec.validate(tags=["user"])
def add_entry(json: EntryInput):
    models.create_entry(json.name, json.amount, json.category)
    return {"message" : "Création réussie"}

@api.route("/user", methods=["GET"])
@auth.login_required
@spec.validate(tags=["user"])
def get_all():
    entries = models.get_all_entries()
    return jsonify([entry.__dict__ for entry in entries])


@api.route("/user/<uuid:id>", methods=["GET"])
@auth.login_required
@spec.validate(tags=["user"])
def get_one(id):
    entry = models.get_entry(id)
    return jsonify(entry.__dict__)


@api.route("/user/<uuid:id>", methods=["PUT"])
@auth.login_required
@spec.validate(json=EntryInput, tags=["user"])
def update_entry(id, json: EntryInput):
    models.update_entry(id, json.name, json.amount, json.category)
    return {"message": "Mise à jour réussie"}


@api.route("/user/<uuid:id>", methods=["DELETE"])
@auth.login_required
@spec.validate(tags=["user"])
def delete_entry(id):
    models.delete_entry(id)
    return {"message": "Suppression réussie"}


class File(BaseModel):
    uid: str
    file: BaseFile

@api.route("/user/import", methods=["POST"])
@auth.login_required
@spec.validate(tags=["user"])
def import_csv():
    file_path = request.json.get("file_path")
    models.import_from_csv(file_path)
    return {"message": "Importation réussie depuis le fichier CSV"}


@api.route("/user/export", methods=["GET"])
@auth.login_required
@spec.validate(tags=["user"])
def export_csv():
    file_path = request.args.get("file_path")
    models.export_to_csv(file_path)
    return {"message": "Exportation réussie vers le fichier CSV"}
