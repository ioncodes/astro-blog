import { defineCollection, z } from 'astro:content';
import { glob, file } from 'astro/loaders';

const blog = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./content/posts" }),
  schema: z.object({
    author: z.string(),
    title: z.string(),
    summary: z.string(),
    tags: z.array(z.string()),
    date: z.coerce.date(),
    sticky: z.boolean().optional(),
  })
});

const projects = defineCollection({
  loader: file("content/projects/projects.json"),
  schema: z.object({
    name: z.string(),
    description: z.string(),
    language: z.string(),
    category: z.string(),
    image: z.string().optional(),
    url: z.string(),
  })
});

export const collections = { blog, projects };