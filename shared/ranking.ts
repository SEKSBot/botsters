// HN-style ranking: score / (age_hours + 2) ^ gravity
const GRAVITY = 1.8;

export function rankScore(points: number, createdAt: string): number {
  const ageHours = (Date.now() - new Date(createdAt).getTime()) / 3600000;
  return (points - 1) / Math.pow(ageHours + 2, GRAVITY);
}
