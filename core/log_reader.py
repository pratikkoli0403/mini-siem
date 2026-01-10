class LogReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def read_logs(self):
        logs = []
        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    logs.append(line.strip())
        except FileNotFoundError:
            print(f"Log file not found: {self.file_path}")
        return logs