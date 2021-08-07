# HullEncrypt

## Idea

HullEncrypt (base and gui) are inspired by [Skeleton](https://github.com/cs-bic/skeleton)

Imagine a Tree of nodes :
	Root -> Child1 -> GrandChild1

All children can be unlocked with the key of their parents
and by their own password (if set)

This could be used as a simple password manager, where every employee has encrypted passwords, that their co workers can't access, with the employer being able to see every password


## Keys, parent_keys and how they work

Each node has it's own key, wich is used to encrypt the content of the node, and unlock the children of the node

This key can be obtained in multiple ways

### parent_keys
The key can be derived from the key of the parent + the nodes name hashed
### passwords
The key also exists in an encrypted state as an attribute of the node called enc_key. The encrpyted key can be unlocked by the password.


## Gui

A simple implementation of the Node class in a GUI

## Im / Ex porting

Roots can be exported and imported as .json files

### Nodes

While nodes CAN be exported and imported from files
You will need to set a password for them if you want to import them without the original root

## Straight Python

You can obviously ditch the GUI entirely and create your own applications with the base file

example : 

```py
import base
import os

root_node = base.Node("root_node", parent_key=os.urandom(16), content="root_content", password="example")
root_key = root_node.get_key(password="example")
child = base.Node("child1", parent_key=root_key, content="not_root")
root_node.add_child(child)

child = root_node.get_child_node(["child1"]) # if you reference to children you can get them by path (also their keys)
child.get_content(parent_key=root_key)
```
