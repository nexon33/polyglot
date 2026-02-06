// Simple React-style component
export const App = () => {
    const [count, setCount] = React.useState(0);
    
    return (
        <div className="app">
            <h1>Poly Split Output Test</h1>
            <p>Count: {count}</p>
            <button onClick={() => setCount(c => c + 1)}>Increment</button>
        </div>
    );
};