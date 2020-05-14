import os
import unittest

from node.tests import NodeTestCase
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from cone.sql.ugm import SQLPrincipal as Principal, SQLUser, Base, SQLGroup, Ugm, Group, User, Groups, Users

from cone.sql import testing


def temp_database(fn):
    """
    This decorator creates an in-memory sqlite db for testing the user classes

    """

    def wrapper(self):
        curdir = os.path.dirname(__file__)
        fname = "%s/test.db" % curdir
        if os.path.exists(fname):
            os.remove(fname)
        uri = "sqlite:///" + fname
        engine = create_engine(uri)
        Base.metadata.create_all(engine)
        sm = sessionmaker(bind=engine)
        session = sm()
        fn(self, session)

    return wrapper


class UsersTestCase(unittest.TestCase):

    @temp_database
    def test_db(self, session):
        print(session)

    @temp_database
    def test_create_user(self, session):
        for name in ["phil", "donald", "dagobert", "daisy"]:
            session.add(SQLUser(id=name))

        session.flush()

        users = session.query(SQLUser).all()
        usernames = [u.id for u in users]
        assert "phil" in usernames

        for group in ["admins", "losers", "members", "editors", "phil"]:
            session.add(SQLGroup(id=group))

        session.flush()

        phil = session.query(SQLUser).filter(SQLUser.id == "phil").one()
        donald = session.query(SQLUser).filter(SQLUser.id == "donald").one()
        admins = session.query(SQLGroup).filter(SQLGroup.id == "admins").one()
        losers = session.query(SQLGroup).filter(SQLGroup.id == "losers").one()
        members = session.query(SQLGroup).filter(SQLGroup.id == "members").one()

        phil.principal_roles = ["manager", "member"]

        phil.groups.append(admins)
        phil.groups.append(members)

        donald.groups.append(losers)
        donald.groups.append(members)
        session.flush()

        phil1 = session.query(SQLUser).filter(SQLUser.id == "phil").one()
        donald1 = session.query(SQLUser).filter(SQLUser.id == "donald").one()

        assert "manager" in phil1.principal_roles

        assert admins in phil1.groups
        assert members in phil1.groups

        losers1 = session.query(SQLGroup).filter(SQLGroup.id == "losers").one()
        members = session.query(SQLGroup).filter(SQLGroup.id == "members").one()
        phil_group = session.query(SQLGroup).filter(SQLGroup.id == "phil").one()

        phil_group.frunz = 42

        assert phil_group.id == phil.id
        assert phil_group.guid != phil.guid

        assert phil in members.users
        assert donald in members.users

        phil_group.users.append(phil)
        assert phil_group in phil.groups

        session.commit()


class TestUserNodes(NodeTestCase):
    layer = testing.sql_layer

    def test_node_users(self):
        self.layer.new_request()

        # setup ugm
        ugm = Ugm()
        users = ugm.users
        groups = ugm.groups

        # create some users with attribute
        ids = ["phil", "donald", "dagobert", "mickey"]
        for count, id in enumerate(ids):
            email = f"{id}@bluedynamics.net"
            users.create(id, height=count+1, email=email, status="super%s" % (count+1))

        # give phil a password
        users.set_hashed_pw("phil", users.hash_passwd("test123"))
        print("hashed pwd:", users["phil"].record.hashed_pw)

        assert "phil" in users
        assert not "zworkb" in users

        assert users.authenticate("phil", "test123")
        assert users["phil"].authenticate("test123")
        assert not users.authenticate("zworkb", "test123")

        # check user attributes
        assert users["phil"].record.data["height"] == 1
        assert users["donald"].record.data["height"] == 2
        assert users["phil"].record.data["status"] == "super1"
        assert users["donald"].record.data["status"] == "super2"

        # check __iter__
        ids1 = list(users)
        assert sorted(ids) == sorted(ids1)
        print(ids1)

        # check login attribute (lets take email)
        # schlumpf and schlumpfine with 2 different login fields
        users.create("schlumpf", email="schlumpf@bluedynamics.net", login="email")
        users.create("schlumpfine", nickname="schlumpfinchen", login="nickname")

        schlumpfid = users.id_for_login("schlumpf@bluedynamics.net")
        schlumpfineid = users.id_for_login("schlumpfinchen")

        assert schlumpfid == "schlumpf"
        assert schlumpfineid == "schlumpfine"

        users.set_hashed_pw(schlumpfid, users.hash_passwd("schlumpf1"))
        users.set_hashed_pw(schlumpfineid, users.hash_passwd("schlumpfine1"))

        print("schlumpf ID:", schlumpfid)
        print("schlumpfine ID:", schlumpfineid)

        assert users.authenticate(schlumpfid, "schlumpf1")
        assert users.authenticate(schlumpfineid, "schlumpfine1")
        users.session.commit()

        # And now the groups
        managers = groups.create("managers", title="Masters of the Universe")
        members = groups.create("members", title="the normal ones")
        managers1 = groups["managers"]

        assert managers1.record.data["title"] == "Masters of the Universe"
        assert groups.ugm is not None

        managers.add("phil")
        for id in ids:
            members.add(id)
        users.session.commit()
        assert "phil" in managers.member_ids

        phil2 = managers["phil"]
        assert isinstance(phil2, User)

        ## non group members should raise a KeyError
        self.assertRaises(KeyError, lambda: managers['donald'])

        for id in ids:
            assert id in members.member_ids

        # Role management
        ## roles for a user
        users["phil"].add_role("Editor")
        users["phil"].add_role("Spam")
        assert "Editor" in users["phil"].roles
        assert "Spam" in users["phil"].roles

        users["phil"].remove_role("Spam")
        assert "Spam" not in users["phil"].roles
        users.session.commit()
        ## removing non-existing roles is tolerated
        users["phil"].remove_role("Spam")

        ## roles for group
        groups["managers"].add_role("Manager")
        groups["members"].add_role("Member")
        assert "Manager" in groups["managers"].roles

        ## cumulative roles for the user -> user has all roles by his groups
        assert "Manager" in users["phil"].roles
        assert users["phil"].roles == set(("Manager", "Editor", "Member"))

        ## get group instances of a user
        for g in users["phil"].groups:
            assert isinstance(g, Group)

        ## group_ids shall match group instances
        assert set(users["phil"].group_ids) == set([g.id for g in users["phil"].groups])

        ## delete a group membership
        del managers["phil"]
        # users.session.flush()
        users.session.commit()  # needs commit, flush() is not sufficient
        assert users["phil"] not in managers.users  # needs refresh
        assert users["phil"] not in groups["managers"].users
        assert "phil" not in managers.member_ids
        assert "managers" not in users["phil"].group_ids
        assert groups["managers"] not in users["phil"].groups

        ## test iter
        assert set(ids) == set(list(members))

        # ugm-level role management
        ugm.add_role("Snuff", users["phil"])
        assert "Snuff" in users["phil"].roles

        ugm.add_role("Smurf", groups["managers"])
        assert "Smurf" in groups["managers"].roles

        ugm.remove_role("Snuff", users["phil"])
        assert "Snuff" not in users["phil"].roles

        ugm.remove_role("Smurf", groups["managers"])
        assert "Smurf" not in groups["managers"].roles

        # searching

        # r1 = users.search(
        #     criteria=dict(
        #         height=1
        #     )
        # )
        # assert len(r1) == 1
        # assert r1[0].id == "phil"

        r2 = users.search(
            criteria=dict(
                status="super1"
            )
        )
        assert len(r2) == 1
        assert r2[0].id == "phil"

        print("ready")
