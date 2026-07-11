"""Entry point for the HYDRA TUI."""


def main():
    from control_center.app import HydraApp
    app = HydraApp()
    app.run()


if __name__ == "__main__":
    main()
