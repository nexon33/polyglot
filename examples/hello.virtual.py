def greet(name):
    """Python function to greet someone"""
    return f"Hello, {name}!"

def calculate_stats(values):
    """Calculate basic statistics"""
    n = len(values)
    mean = sum(values) / n
    return {"count": n, "sum": sum(values), "mean": mean}

#[js]
const render = (data) => {
    console.log("Rendering:", data);
    return { type: "chart", data: data };
};

const formatCurrency = (amount, currency = "USD") => {
    return `${currency} ${amount.toFixed(2)}`;
};