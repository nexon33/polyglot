fn greet(name):
        """Python function to greet someone"""
        return format!("Hello, {name}!")

    fn calculate_stats(values):
        """Calculate basic statistics"""
        n = len(values)
        mean = sum(values) / n
        return {"count": n, "sum": sum(values), "mean": mean}