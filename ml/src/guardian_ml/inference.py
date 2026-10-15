import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

from guardian_ml import GuardianModel


def main():
    parser = argparse.ArgumentParser(description='Guardian ML inference')
    parser.add_argument('--model', type=Path, default=Path('api/models/model.joblib'), help='Model path')
    parser.add_argument('--urls', nargs='+', help='URLs to analyze')
    parser.add_argument('--input', type=Path, help='JSON/JSONL file with URLs')
    parser.add_argument('--output', type=Path, help='Output JSON file')
    parser.add_argument('--format', choices=['json', 'table'], default='table', help='Output format')
    parser.add_argument('--model-type', choices=['lightgbm', 'logistic_regression'], default='lightgbm', help='Model to use')
    args = parser.parse_args()

    print(f"Loading model from {args.model}...")
    model = GuardianModel.load(args.model)

    urls = []
    if args.urls:
        urls.extend(args.urls)
    if args.input:
        with open(args.input) as f:
            if args.input.suffix == '.jsonl':
                for line in f:
                    record = json.loads(line)
                    urls.append(record['url'])
            else:
                data = json.load(f)
                if isinstance(data, list):
                    urls.extend([d['url'] if isinstance(d, dict) else d for d in data])
                elif isinstance(data, dict) and 'urls' in data:
                    urls.extend(data['urls'])

    if not urls:
        parser.error("No URLs provided. Use --urls or --input")

    print(f"Analyzing {len(urls)} URLs with {args.model_type}...")
    results = model.predict_batch(urls, model_name=args.model_type)

    output_data = []
    for url, result in zip(urls, results):
        data = {
            'url': url,
            'is_malicious': result.is_malicious,
            'probability': result.probability,
            'confidence': result.confidence,
            'risk_score': result.risk_score,
            'risk_level': result.risk_level,
            'signals': result.signals,
            'top_contributions': result.top_contributions,
        }
        output_data.append(data)

        if args.format == 'table':
            status = "MALICIOUS" if result.is_malicious else "BENIGN"
            print(f"\n{url}")
            print(f"  Status: {status} (probability: {result.probability:.2%}, confidence: {result.confidence:.2%})")
            print(f"  Risk: {result.risk_level} ({result.risk_score}/100)")
            if result.signals:
                print(f"  Signals:")
                for s in result.signals:
                    print(f"    - {s['label']}: {s['reason']} ({s['points']} pts)")
            if result.top_contributions:
                print(f"  Top Contributions:")
                for c in result.top_contributions[:5]:
                    print(f"    - {c['feature']}: {c['contribution']:.4f} ({c['direction']})")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == '__main__':
    main()