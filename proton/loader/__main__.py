if __name__ == '__main__':
    from . import Loader

    print("Available loaders:")
    for type_name in sorted(Loader.type_names):
        print(f'  - {type_name}:')
        for prio, class_name, cls in Loader.get_all(type_name):
            print(f'    - {class_name:30s} [{prio}]')
