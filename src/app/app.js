import { html } from 'https://cdn.jsdelivr.net/npm/htm@4.0.5/dist/htm.min.mjs';

const hello = () => {
    return html`
        <h1>Hello, World!</h1>
    `;
};

export default function App() {
    return (
        <>
            ${hello()}
        </>
    );
}