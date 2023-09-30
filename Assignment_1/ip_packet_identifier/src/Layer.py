class Layer():
    def __init__(self, packet) -> None:
        self.packet = packet

    def get_layer(self):
        return self.packet