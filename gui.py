import json
import os
import sys

from PySide6 import QtWidgets, QtCore, QtGui

import base


class MyWidget(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        loaded_json = "{}"
        # load the test json
        self.password = self.get_input("password", "Password for new tree")
        self.root_node = base.Node("root_node", os.urandom(16), password=self.password)
        self.load_json(loaded_json, self.root_node, self.get_root_key())

        # Objects on the left
        self.loadArea = QtWidgets.QHBoxLayout()
        self.fullLoadButton = QtWidgets.QPushButton("load to root")
        self.partialLoadButton = QtWidgets.QPushButton("load to node")


        self.tree = QtWidgets.QTreeWidget()
        self.groot_node = QtWidgets.QTreeWidgetItem(["root_node"])
        self.tree.addTopLevelItem(self.groot_node)

        self.creation_area = QtWidgets.QHBoxLayout()
        self.removeNodeButton = QtWidgets.QPushButton("Remove node")
        self.addNodeButton = QtWidgets.QPushButton("Add node")
        self.renameButton = QtWidgets.QPushButton("Rename node")

        self.groot_node.addChildren(self.create_gnodes(self.root_node))
        self.groot_node.path = []
        self.groot_node.node = self.root_node

        # Objects on the right
        self.updateSection = QtWidgets.QHBoxLayout()
        self.saveButton = QtWidgets.QPushButton("Update Content")
        self.contentBox = QtWidgets.QTextEdit()
        self.exportNodeButton = QtWidgets.QPushButton("Export Node to json")
        self.exportAllButton = QtWidgets.QPushButton("Export All to json")
        self.passwordButton = QtWidgets.QPushButton("Update Password")

        self.right_side = QtWidgets.QVBoxLayout()
        self.left_side = QtWidgets.QVBoxLayout()

        self.layout = QtWidgets.QHBoxLayout(self)
        self.layout.addLayout(self.left_side)
        self.layout.addLayout(self.right_side)

        self.left_side.addLayout(self.loadArea)
        self.loadArea.addWidget(self.fullLoadButton)
        self.loadArea.addWidget(self.partialLoadButton)
        self.left_side.addWidget(self.tree)
        self.left_side.addLayout(self.creation_area)
        self.creation_area.addWidget(self.addNodeButton)
        self.creation_area.addWidget(self.removeNodeButton)
        self.creation_area.addWidget(self.renameButton)

        self.right_side.addLayout(self.updateSection)
        self.updateSection.addWidget(self.saveButton)
        self.updateSection.addWidget(self.passwordButton)
        self.right_side.addWidget(self.contentBox)
        self.right_side.addWidget(self.exportAllButton)
        self.right_side.addWidget(self.exportNodeButton)


        # Connects
        self.tree.currentItemChanged.connect(self.updateContentBox)
        self.saveButton.pressed.connect(self.updateContent)
        self.exportAllButton.pressed.connect(self.startAllJsonExport)
        self.exportNodeButton.pressed.connect(self.startNodeJsonExport)
        self.fullLoadButton.pressed.connect(self.load_to_root)
        self.partialLoadButton.pressed.connect(self.load_to_node)
        self.addNodeButton.pressed.connect(self.addNode)
        self.removeNodeButton.pressed.connect(self.removeNode)
        self.renameButton.pressed.connect(self.renameNode)
        self.passwordButton.pressed.connect(self.changeNodePassword)

    def changeNodePassword(self):
        try:
            path = self.tree.currentItem().path
        except:
            self.show_exception("No node selected")
            return

        node = self.root_node.get_child_node(path)
        new_password = self.get_input("Password", f"New Password for {node.name}")
        if not new_password:
            self.show_exception("No Password entered")
            return
        key = self.root_node.get_child_key(self.get_root_key(), path[:-1])
        node.set_password(parent_key=key, password=new_password)

    def renameNode(self):
        path = self.tree.currentItem().path
        if not path and path != []:
            self.show_exception("No node selected")
            return
        elif path == []:
            self.show_exception("Root can't be renamed")
            return
        new_name = self.get_input("rename", "input new name")
        node = self.root_node.get_child_node(path)
        node.rename(new_name, parent_key=self.root_node.get_child_key(self.get_root_key(), path[:-1]))

        self.tree.currentItem().path = path[:-1]
        self.tree.currentItem().path.append(new_name)

        self.tree.currentItem().setText(0, new_name)
    def get_input(self, title, question):
        text, ok = QtWidgets.QInputDialog.getText(self, title, question)
        return text
    def get_password(self, title, question):
        text, ok = PasswordGetter(self, title, question)
        return text
    def addNode(self):
        path = ""
        try:
            path = self.tree.currentItem().path
        except:
            self.show_exception("No Node selected")
            return
        new_name = self.get_input("Node creation", "What should the name of the new node be")
        if not new_name:
            new_name = "New Node"
        try:
            new = base.Node(new_name, self.root_node.get_child_key(self.get_root_key(), path))
        except:
            self.show_exception("Node with that name already exists")
            return
        parent_node = self.root_node.get_child_node(path)
        parent_node.add_child(new)
        new_gnode = QtWidgets.QTreeWidgetItem([new_name])
        new_gnode.path = path.copy()
        new_gnode.path.append(new_name)
        new_gnode.node = new
        self.tree.currentItem().addChild(new_gnode)

    def removeNode(self):
        path = self.tree.currentItem().path
        if not path and path != []:
            self.show_exception("No Node selected")
            return
        elif path == []:
            self.show_exception("root can't be deleted")
            return
        else:
            to_delete = self.root_node.get_child_node(path)
            parent_node = self.root_node.get_child_node(path[:-1])
            parent_node.children.remove(to_delete)
            self.tree.currentItem().parent().removeChild(self.tree.currentItem())



    def create_gnodes(self, root_node, path=None):
        if not path:
            path = []
        nodes = []
        for child in root_node.children:
            child_gnode = QtWidgets.QTreeWidgetItem([child.displayname])
            child_gnode.node = child
            local_path = path.copy()
            local_path.append(child.name)
            child_gnode.path = local_path
            if child.children:
                child_gnode.addChildren(self.create_gnodes(child, local_path))
            nodes.append(child_gnode)

        return nodes

    def load_json(self, node_json, parent_node, parent_key):
        users = json.loads(node_json)
        if "global_key" in users.keys():
            parent_node.enc_key = bytes.fromhex(users["global_key"])
            parent_node.before_fakeroot = parent_node.name
            parent_node.name = "root_node"
            try:
                if parent_node == self.root_node:
                    self.password = self.get_input("Root password", "Enter root password")
                    parent_key = parent_node.get_key(password=self.password)

            except Exception as e:
                print(e)
                if parent_node == self.root_node:
                    self.show_exception("invalid root password")
                    self.tree.clear()
                    self.root_node = base.Node("root_node", os.urandom(16), password=self.password)

                    self.groot_node = QtWidgets.QTreeWidgetItem(["root_node"])
                    self.groot_node.path = []
                    self.groot_node.node = self.root_node
                    self.tree.addTopLevelItem(self.groot_node)
                    return
        for user in users:
            if user == "global_key":
                continue

            user_node = base.Node(user, parent_key)
            user_node.content = bytes.fromhex(users[user]["content"])
            if "children" in users[user].keys():
                self.load_json(
                    users[user]["children"],
                    user_node,
                    user_node.get_key(parent_key=parent_key)
                )

            if "enc_key" in users[user].keys():
                user_node.enc_key = bytes.fromhex(users[user]["enc_key"])

            parent_node.add_child(user_node)
        if "global_key" in users.keys() and parent_node != self.root_node:
            passw = self.get_input("fakeroot", "password for fakeroot")
            path = self.tree.currentItem().path
            enc_key = bytes.fromhex(users["global_key"])
            parent_node.enc_key = enc_key
            parent_node.rename(parent_node.before_fakeroot, password=passw, new_parent_key=self.root_node.get_child_key(self.get_root_key(), path[:-1]))

    def load_to_root(self):
        try:
            parent_key = self.get_root_key(disable_popup=True)
        except base.fernet.InvalidToken:
            # in case a TEMP root_node wasn't cleared due to
            # loading a subdir as root
            self.password = "TEMP"
            parent_key = self.get_root_key()
        open_path, file_type = QtWidgets.QFileDialog.getOpenFileName(self)
        if not open_path:
            return
        self.tree.clear()
        self.groot_node = QtWidgets.QTreeWidgetItem(["root_node"])
        self.groot_node.path = []
        self.tree.addTopLevelItem(self.groot_node)
        # this is in case you load a sub path without password
        # wich wouldn't reset the node but the visual
        # leaving ghost nodes
        self.root_node = base.Node("root_node", os.urandom(16), password="TEMP")
        f = open(open_path, "r")
        loaded_json = f.read()
        f.close()
        self.load_json(loaded_json, self.root_node, parent_key)
        print("loaded backend")
        self.groot_node.addChildren(self.create_gnodes(self.root_node))

    def load_to_node(self):
        try:
            path = self.tree.currentItem().path
        except:
            self.show_exception("No node selected")
            return
        if path == []:
            self.show_exception("Don't use 'load to node' for loading to root")
            return
        parent_key = self.root_node.get_child_key(self.get_root_key(), path)
        open_path, file_type = QtWidgets.QFileDialog.getOpenFileName(self)
        f = open(open_path, "r")
        loaded_json = f.read()
        f.close()
        self.load_json(node_json=loaded_json, parent_node=self.root_node.get_child_node(self.tree.currentItem().path), parent_key=parent_key)
        print("loaded backend")
        self.tree.currentItem().addChildren(
            self.create_gnodes(
                self.root_node.get_child_node(path),
                path)
        )

    def get_root_key(self, disable_popup=False):
        try:
            return self.root_node.get_key(password=self.password)
        except base.fernet.InvalidToken:
            if disable_popup:
                raise
            else:
                self.show_exception("Root password invalid")
                raise

    def show_exception(self, text):
        box = QtWidgets.QMessageBox()
        box.setText(text)
        box.exec()

    def updateContentBox(self):
        treeItem = self.tree.currentItem()
        if not treeItem:
            self.contentBox.setText("Nothing Selected")
            return
        print(treeItem.path)
        root_key = self.get_root_key()
        key = self.root_node.get_child_key(key=root_key, path=treeItem.path)
        if treeItem.path:
            try:
                self.contentBox.setText(treeItem.node.get_content(key))
            except base.fernet.InvalidToken:
                self.show_exception("Token invalid")
        else:
            self.contentBox.setText("RootNode")

    def updateContent(self):
        treeItem = self.tree.currentItem()
        print(treeItem.path)
        if treeItem.path:
            root_key = self.get_root_key()
            key = self.root_node.get_child_key(root_key, treeItem.path)
            try:
                treeItem.node.update_content(key=key, content=self.contentBox.toPlainText())
            except base.fernet.InvalidToken:
                self.show_exception("Wrong root password")
                print("cringe")
                raise
            except Exception as e:
                self.show_exception("Wrong root password")
                raise
        else:
            xd = QtWidgets.QMessageBox()
            xd.setText("Text of root_node can never be updated")
            xd.exec()

    def startAllJsonExport(self):
        print("Doing it")
        export_path, file_format = QtWidgets.QFileDialog.getSaveFileName(self, "save nodes as json", os.getcwd(),
                                                                         "*.json")
        self.exportAllToJson(export_path)

    def startNodeJsonExport(self):
        print("Doing it")
        try:
            self.tree.currentItem().path
        except:
            self.show_exception("No Node selected")
            return

        export_path, file_format = QtWidgets.QFileDialog.getSaveFileName(self, "save nodes as json", os.getcwd(),
                                                                         "*.json")
        self.exportNodeToJson(export_path)

    def nodeToJson(self, node):
        if node.enc_key:
            json_dict = {"global_key": node.enc_key.hex()}
        else:
            json_dict = {} 
        for child in node.children:
            json_dict[child.name] = {}
            json_dict[child.name]["content"] = child.content.hex()
            print(node)
            if child.children:
                json_dict[child.name]["children"] = self.nodeToJson(child)
        print("json" + str(json_dict))
        return json.dumps(json_dict)

    def exportNodeToJson(self, export_path):
        node = self.root_node.get_child_node(self.tree.currentItem().path)
        path = self.tree.currentItem().path
        parent_key = self.root_node.get_child_key(self.get_root_key(), path[:-1])
        old_name = node.name
        passw = node.get_pass(parent_key=parent_key)
        node.rename("root_node", password=passw, parent_key=parent_key)
        text = self.nodeToJson(node)
        node.rename(old_name, password=passw, parent_key=parent_key)
        f = open(export_path, "w")
        f.write(text)
        f.close()

    def exportAllToJson(self, export_path):
        text = self.nodeToJson(self.root_node)
        f = open(export_path, "w")
        f.write(text)
        f.close()


if __name__ == "__main__":
    app = QtWidgets.QApplication([])

    widget = MyWidget()
    widget.resize(800, 600)
    widget.show()

    sys.exit(app.exec())
