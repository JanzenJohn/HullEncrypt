import base
import os

root_node = base.Node(
                parent_key=os.urandom(16),
                name="root_node".encode("utf-8"),
                content="root_node_content".encode("utf-8"),
                password="sample_password".encode("utf-8")
                )

root_key = root_node.get_key(password='sample_password'.encode("utf-8"))

root_content = root_node.get_content(key=root_key)

assert root_content == "root_node_content".encode("utf-8")

child_one = base.Node(
                parent_key=root_key,
                name="child_one".encode("utf-8"),
                content="child_content_one".encode("utf-8")
                )

root_node.children.append(child_one)

child_key = root_node.get_child_key(root_key, ["child_one".encode("utf-8")])

child_content = child_one.get_content(key=child_key)

assert child_content == "child_content_one".encode("utf-8")
